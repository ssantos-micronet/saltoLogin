using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Web;
using Newtonsoft.Json.Linq;
using System.Data.SqlClient;
using System.IO;

class RegistrationApp
{
    private static string connectionString;

    static async Task Main(string[] args)
    {
        connectionString = ReadConnectionStringFromFile("connectionString.txt");
        var accessToken = await GetAccessToken();

        if (string.IsNullOrEmpty(accessToken))
        {
            Console.WriteLine("Falha ao obter o token de acesso.");
            return;
        }

        // Store token and user info
        // Note: This line was updated to pass the token response content
        // await StoreUserInfo(accessToken, tokenResponseContent); // Move this logic into GetAccessToken
    }

private static async Task<string> GetClientIdFromDatabase(string connectionString)
{
    string clientId = null;

    try
    {
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            await connection.OpenAsync();

            // Consulta para buscar o clientId da tabela xsetup
            string query = @"
                SELECT xvalue 
                FROM [dbo].[xsetup] 
                WHERE xsection = 'SysConector' 
                AND xkey = 'clientId'";

            using (SqlCommand command = new SqlCommand(query, connection))
            {
                clientId = (string)await command.ExecuteScalarAsync(); // Retorna o valor da primeira linha
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine("Erro ao buscar o clientId do banco de dados: " + ex.Message);
        // Opcional: logar o erro ou tomar alguma ação
    }

    return clientId;
}

    private static async Task<string> GetAccessToken()
{
    var clientId = await GetClientIdFromDatabase(connectionString); // Busca o clientId do banco de dados

    if (string.IsNullOrEmpty(clientId))
    {
        Console.WriteLine("Falha ao obter o clientId do banco de dados.");
        return null;
    }

    var redirectUri = "https://app-accept.saltoks.com/callback";
    var scope = "user_api.full_access openid profile offline_access";
    var authorizationEndpoint = "https://clp-accept-identityserver.saltoks.com/connect/authorize";
    var tokenUrl = "https://clp-accept-identityserver.saltoks.com/connect/token";

    var codeVerifier = PKCEHelper.GenerateCodeVerifier();
    var codeChallenge = PKCEHelper.GenerateCodeChallenge(codeVerifier);
    var codeChallengeMethod = "S256";

    var authorizationUrl = $"{authorizationEndpoint}?response_type=code" +
                            $"&client_id={clientId}" +
                            $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                            $"&scope={Uri.EscapeDataString(scope)}" +
                            $"&code_challenge={codeChallenge}" +
                            $"&code_challenge_method={codeChallengeMethod}";

    Console.WriteLine("A abrir o navegador para autorização...");
    Process.Start(new ProcessStartInfo
    {
        FileName = authorizationUrl,
        UseShellExecute = true
    });

    Console.WriteLine("Cole o URL completo de callback aqui:");
    var callbackUrl = Console.ReadLine();

    var authorizationCode = ExtractAuthorizationCode(callbackUrl);

    if (string.IsNullOrEmpty(authorizationCode))
    {
        Console.WriteLine("Falha ao extrair o código de autorização do URL.");
        return null;
    }

    using (var httpClient = new HttpClient())
    {
        var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl);
        var parameters = new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", authorizationCode },
            { "redirect_uri", redirectUri },
            { "client_id", clientId },
            { "code_verifier", codeVerifier }
        };

        request.Content = new FormUrlEncodedContent(parameters);
        var response = await httpClient.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();

        if (response.IsSuccessStatusCode)
        {
            var json = JObject.Parse(content);
            var accessToken = json["access_token"]?.ToString();
            
            // Store user info and tokens
            await StoreUserInfo(accessToken, content); // Pass both accessToken and content

            return accessToken;
        }
        else
        {
            Console.WriteLine("Erro ao obter token: " + content);
            return null;
        }
    }
}


    private static string? ExtractRefreshToken(string jsonResponse)
    {
        var json = JObject.Parse(jsonResponse);
        return json["refresh_token"]?.ToString();
    }

    private static string? ExtractAuthorizationCode(string callbackUrl)
    {
        if (string.IsNullOrEmpty(callbackUrl)) return null;

        var uri = new Uri(callbackUrl);
        var query = HttpUtility.ParseQueryString(uri.Query);
        return query["code"];
    }

    private static async Task StoreUserInfo(string accessToken, string tokenResponseContent)
    {
        var userData = await FetchUserData(accessToken); // Fetch user-specific data
        var refreshToken = ExtractRefreshToken(tokenResponseContent); // Extract the refresh token from the content
        var expiration = DateTime.UtcNow.AddMinutes(60); // Set expiration time

        using (var connection = new SqlConnection(connectionString))
        {
            await connection.OpenAsync();
            var query = @"INSERT INTO requestConfig (accessToken, refreshToken, tokenExpiration, userData)
                          VALUES (@AccessToken, @RefreshToken, @TokenExpiration, @UserData)";

            using (var command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@AccessToken", accessToken);
                command.Parameters.AddWithValue("@RefreshToken", (object)refreshToken ?? DBNull.Value);
                command.Parameters.AddWithValue("@TokenExpiration", expiration);
                command.Parameters.AddWithValue("@UserData", userData);

                await command.ExecuteNonQueryAsync();
            }
        }
    }

    private static async Task<string> FetchUserData(string accessToken)
    {
        // Implement your logic to fetch user data from the API
        return "{}"; // Return user data as a JSON string
    }

    private static string ReadConnectionStringFromFile(string filePath)
    {
        return File.ReadAllText(filePath).Trim();
    }
}