namespace AutoParts_Link_Website.Models;

public class User
{
    public int Id { get; set; }

    public string FullName { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    public string PasswordSalt { get; set; } = string.Empty;

    public string Role { get; set; } = "Buyer";

    public string? PhoneNumber { get; set; }

    // New accounts must be approved by an administrator.
    public string Status { get; set; } = "Pending";
    


    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}