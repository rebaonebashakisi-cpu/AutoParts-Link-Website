using AutoParts_Link_Website.Data;
using AutoParts_Link_Website.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace AutoParts_Link_Website.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly AppDbContext _context;

    public AccountController(AppDbContext context)
    {
        _context = context;
    }

    public class RegisterRequest
    {
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Role { get; set; } = "Buyer";
        public string? PhoneNumber { get; set; }
    }

    public class LoginRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.FullName) ||
            string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new
            {
                message = "Name, email and password are required."
            });
        }

        if (request.Password.Length < 8)
        {
            return BadRequest(new
            {
                message = "Password must be at least 8 characters."
            });
        }

        string email = request.Email.Trim().ToLowerInvariant();

        if (await _context.Users.AnyAsync(u => u.Email == email))
        {
            return Conflict(new
            {
                message = "This email is already registered."
            });
        }

        string role = request.Role.Trim().ToLowerInvariant();

        if (role != "buyer" &&
            role != "seller" &&
            role != "mechanic")
        {
            return BadRequest(new
            {
                message = "Role must be Buyer, Seller or Mechanic."
            });
        }

        byte[] saltBytes = RandomNumberGenerator.GetBytes(16);
        string passwordSalt = Convert.ToBase64String(saltBytes);

        string passwordHash = Convert.ToBase64String(
            Rfc2898DeriveBytes.Pbkdf2(
                request.Password,
                saltBytes,
                100000,
                HashAlgorithmName.SHA256,
                32));

        var user = new User
        {
            FullName = request.FullName.Trim(),
            Email = email,
            PasswordHash = passwordHash,
            PasswordSalt = passwordSalt,
            Role = role,
            PhoneNumber = request.PhoneNumber?.Trim(),
            Status = "Pending"
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return Ok(new
        {
            message = "Account created. Please wait for administrator approval.",
            userId = user.Id,
            fullName = user.FullName,
            email = user.Email,
            role = user.Role,
            status = user.Status
        });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new
            {
                message = "Email and password are required."
            });
        }

        string email = request.Email.Trim().ToLowerInvariant();

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email);

        if (user == null)
        {
            return Unauthorized(new
            {
                message = "Invalid email or password."
            });
        }

        byte[] saltBytes;

        try
        {
            saltBytes = Convert.FromBase64String(user.PasswordSalt);
        }
        catch (FormatException)
        {
            return Unauthorized(new
            {
                message = "Invalid email or password."
            });
        }

        byte[] expectedHash;

        try
        {
            expectedHash = Convert.FromBase64String(user.PasswordHash);
        }
        catch (FormatException)
        {
            return Unauthorized(new
            {
                message = "Invalid email or password."
            });
        }

        byte[] suppliedHash = Rfc2898DeriveBytes.Pbkdf2(
            request.Password,
            saltBytes,
            100000,
            HashAlgorithmName.SHA256,
            32);

        if (expectedHash.Length != suppliedHash.Length ||
            !CryptographicOperations.FixedTimeEquals(
                expectedHash, suppliedHash))
        {
            return Unauthorized(new
            {
                message = "Invalid email or password."
            });
        }

        string status = user.Status ?? "Pending";

        if (status.Equals("Pending", StringComparison.OrdinalIgnoreCase))
        {
            return StatusCode(403, new
            {
                message = "Your account is waiting for administrator approval.",
                status = status
            });
        }

        if (status.Equals("Rejected", StringComparison.OrdinalIgnoreCase))
        {
            return StatusCode(403, new
            {
                message = "Your account was rejected. Please contact the administrator.",
                status = status
            });
        }

        if (!status.Equals("Approved", StringComparison.OrdinalIgnoreCase))
        {
            return StatusCode(403, new
            {
                message = "Your account is not approved for access.",
                status = status
            });
        }

        return Ok(new
        {
            message = "Login successful.",
            userId = user.Id,
            fullName = user.FullName,
            name = user.FullName,
            email = user.Email,
            role = user.Role.ToLowerInvariant(),
            status = user.Status
        });
    }
}