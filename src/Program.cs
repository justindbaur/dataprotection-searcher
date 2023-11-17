using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.AspNetCore.WebUtilities;

class Program
{
    async static Task Main(string[] args)
    {
        if (args.Length != 1)
        {
            throw new ArgumentException("Expected 1 arguments, [connection-string]");
        }

        // var services = new ServiceCollection();

        // var builder = services.AddDataProtection(options =>
        // {
        //     options.ApplicationDiscriminator = "Bitwarden";
        // });

        // var keysDirectory = new DirectoryInfo(args[1]);
        // if (!keysDirectory.Exists)
        // {
        //     throw new ArgumentException($"Given keys directory '{args[1]}' does not exist.");
        // }

        // builder.PersistKeysToFileSystem(keysDirectory);

        // var provider = services.BuildServiceProvider();

        // var keyManager = provider.GetRequiredService<IKeyManager>();
        // var keys = keyManager.GetAllKeys();

        // var decryptor = provider.GetRequiredService<IDataProtectionProvider>();
        // Console.WriteLine(decryptor.GetType().FullName);

        var users = await GetUsers(args[0]);
        foreach (var user in users)
        {
            Guid? masterPasswordKeyId = null;
            if (!string.IsNullOrEmpty(user.MasterPassword) && user.MasterPassword.StartsWith("P|"))
            {
                var masterPasswordBytes = WebEncoders.Base64UrlDecode(user.MasterPassword[2..]);
                if (TryReadKeyId(masterPasswordBytes, out var keyId))
                {
                    masterPasswordKeyId = keyId;
                }
            }

            Guid? keyKeyId = null;
            if (!string.IsNullOrEmpty(user.Key) && user.Key.StartsWith("P|"))
            {
                var keyBytes = WebEncoders.Base64UrlDecode(user.Key[2..]);
                if (TryReadKeyId(keyBytes, out var keyId))
                {
                    keyKeyId = keyId;
                }
            }

            Console.WriteLine($"{user.Id},{masterPasswordKeyId},{keyKeyId}");
        }
    }

    // Ref: https://github.com/dotnet/aspnetcore/blob/4a156ba645cc1910033ec114a770c8ce91505470/src/DataProtection/DataProtection/src/KeyManagement/KeyRingBasedDataProtector.cs#L207
    public static unsafe bool TryReadKeyId(byte[] protectedData, out Guid keyId)
    {
        try
        {
            fixed (byte* pdInput = protectedData)
            {
                keyId = new Guid(new ReadOnlySpan<byte>(&pdInput[sizeof(uint)], sizeof(Guid)));
                return true;
            }
        }
        catch
        {
            keyId = default;
            return false;
        }
    }

    private static async Task<IEnumerable<User>> GetUsers(string connectionString)
    {
        using var connection = new SqlConnection(connectionString);
        var users = await connection.QueryAsync<User>("""
        SELECT [Id], [MasterPassword], [Key]
        FROM [dbo].[User]
        """);
        return users;
    }

    class User
    {
        public Guid Id { get; set; }
        public string? MasterPassword { get; set; }
        public string? Key { get; set; }
    }
}
