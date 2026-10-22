using AutoParts_Link_Website.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace AutoParts_Link_Website.Data;

public static class AdminAccountInitializer
{
    public static async Task InitializeAsync(
        AppDbContext context,
        IConfiguration configuration)
    {
        string? emailSetting = configuration["AdminSetup:Email"];
        string? password = configuration["AdminSetup:Password"];

        if (string.IsNullOrWhiteSpace(emailSetting) ||
            string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException(
                "Admin setup secrets are missing. Configure AdminSetup:Email and AdminSetup:Password using User Secrets.");
        }

        string email = emailSetting.Trim().ToLowerInvariant();

        if (password.Length < 12)
        {
            throw new InvalidOperationException(
                "The initial administrator password must be at least 12 characters.");
        }

        var existingUser = await context.Users
            .FirstOrDefaultAsync(u => u.Email == email);

        if (existingUser != null)
        {
            if (!existingUser.Role.Equals(
                    "admin", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "The configured admin email already belongs to a non-admin account. Choose a different admin email.");
            }

            // An existing admin is left unchanged; this initializer
            // never resets an existing account's password.
            return;
        }

        byte[] saltBytes = RandomNumberGenerator.GetBytes(16);

        string salt = Convert.ToBase64String(saltBytes);

        string hash = Convert.ToBase64String(
            Rfc2898DeriveBytes.Pbkdf2(
                password,
                saltBytes,
                100000,
                HashAlgorithmName.SHA256,
                32));

        var admin = new User
        {
            FullName = "AutoParts Link Administrator",
            Email = email,
            PasswordHash = hash,
            PasswordSalt = salt,
            Role = "admin",
            Status = "Approved"
        };

        context.Users.Add(admin);
        await context.SaveChangesAsync();
    }
}