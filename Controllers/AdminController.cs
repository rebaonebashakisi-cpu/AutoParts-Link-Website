using AutoParts_Link_Website.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AutoParts_Link_Website.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly IConfiguration _configuration;

    public AdminController(
        AppDbContext context,
        IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    // POST: /api/Admin/login
    [HttpPost("login")]
    public async Task<IActionResult> Login(
        [FromBody] AdminLoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrEmpty(request.Password))
        {
            return BadRequest(new
            {
                message = "Email and password are required."
            });
        }

        string email = request.Email.Trim().ToLowerInvariant();

        var admin = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == email);

        if (admin == null ||
            !string.Equals(
                admin.Role, "admin",
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                admin.Status, "Approved",
                StringComparison.OrdinalIgnoreCase))
        {
            return Unauthorized(new
            {
                message = "Invalid administrator credentials."
            });
        }

        byte[] saltBytes;
        byte[] storedHash;

        try
        {
            saltBytes = Convert.FromBase64String(admin.PasswordSalt);
            storedHash = Convert.FromBase64String(admin.PasswordHash);
        }
        catch (FormatException)
        {
            return Unauthorized(new
            {
                message = "Invalid administrator credentials."
            });
        }

        byte[] enteredHash = Rfc2898DeriveBytes.Pbkdf2(
            request.Password,
            saltBytes,
            100000,
            HashAlgorithmName.SHA256,
            32);

        if (storedHash.Length != enteredHash.Length ||
            !CryptographicOperations.FixedTimeEquals(
                storedHash, enteredHash))
        {
            return Unauthorized(new
            {
                message = "Invalid administrator credentials."
            });
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, admin.Id.ToString()),
            new Claim(ClaimTypes.Name, admin.FullName),
            new Claim(ClaimTypes.Email, admin.Email),
            new Claim(ClaimTypes.Role, "admin")
        };

        var identity = new ClaimsIdentity(
            claims,
            CookieAuthenticationDefaults.AuthenticationScheme);

        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal);

        return Ok(new
        {
            message = "Administrator login successful.",
            userId = admin.Id,
            name = admin.FullName,
            email = admin.Email,
            role = "admin"
        });
    }

    // TEMPORARY: Diagnose the admin account.
    // Remove this endpoint before deploying online.
    // GET: /api/Admin/diagnose
    [HttpGet("diagnose")]
    public async Task<IActionResult> Diagnose()
    {
        string? configuredEmail = _configuration["AdminSetup:Email"];

        if (string.IsNullOrWhiteSpace(configuredEmail))
        {
            return Ok(new
            {
                emailConfigured = false,
                accountFound = false
            });
        }

        string email = configuredEmail.Trim().ToLowerInvariant();

        var admin = await _context.Users
            .FirstOrDefaultAsync(u => u.Email.ToLower() == email);

        return Ok(new
        {
            emailConfigured = true,
            accountFound = admin != null,
            role = admin?.Role,
            status = admin?.Status,
            hasPasswordHash =
                !string.IsNullOrWhiteSpace(admin?.PasswordHash),
            hasPasswordSalt =
                !string.IsNullOrWhiteSpace(admin?.PasswordSalt)
        });
    }

    // GET: /api/Admin/pending
    [Authorize(Roles = "admin")]
    [HttpGet("pending")]
    public async Task<IActionResult> GetPendingAccounts()
    {
        var accounts = await _context.Users
            .Where(u => u.Status == "Pending" && u.Role != "admin")
            .OrderBy(u => u.CreatedAt)
            .Select(u => new
            {
                u.Id,
                u.FullName,
                u.Email,
                u.Role,
                u.PhoneNumber,
                u.Status,
                u.CreatedAt
            })
            .ToListAsync();

        return Ok(accounts);
    }

    // GET: /api/Admin/users
    [Authorize(Roles = "admin")]
    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        var users = await _context.Users
            .OrderBy(u => u.CreatedAt)
            .Select(u => new
            {
                u.Id,
                u.FullName,
                u.Email,
                u.Role,
                u.PhoneNumber,
                u.Status,
                u.CreatedAt
            })
            .ToListAsync();

        return Ok(users);
    }

    // POST: /api/Admin/users/delete
    // Permanently deletes selected non-admin accounts.
    [Authorize(Roles = "admin")]
    [HttpPost("users/delete")]
    public async Task<IActionResult> DeleteUsers(
        [FromBody] DeleteUsersRequest request)
    {
        if (request == null ||
            request.Ids == null ||
            request.Ids.Count == 0)
        {
            return BadRequest(new
            {
                message = "Select at least one user to delete."
            });
        }

        var ids = request.Ids.Distinct().ToList();

        if (ids.Any(id => id <= 0))
        {
            return BadRequest(new
            {
                message = "One or more user IDs are invalid."
            });
        }

        // Protect the currently logged-in administrator.
        string? currentAdminId = User.FindFirst(
            ClaimTypes.NameIdentifier)?.Value;

        if (int.TryParse(currentAdminId, out int adminId) &&
            ids.Contains(adminId))
        {
            return BadRequest(new
            {
                message = "You cannot delete your own admin account."
            });
        }

        // Never delete administrator accounts through this endpoint.
        var accounts = await _context.Users
            .Where(u => ids.Contains(u.Id))
            .ToListAsync();

        if (accounts.Any(u =>
            string.Equals(
                u.Role, "admin",
                StringComparison.OrdinalIgnoreCase)))
        {
            return BadRequest(new
            {
                message = "Administrator accounts cannot be deleted."
            });
        }

        if (accounts.Count == 0)
        {
            return NotFound(new
            {
                message = "No matching users were found."
            });
        }

        // Use a transaction so a failed deletion is rolled back.
        await using var transaction =
            await _context.Database.BeginTransactionAsync();

        try
        {
            _context.Users.RemoveRange(accounts);
            await _context.SaveChangesAsync();
            await transaction.CommitAsync();
        }
        catch (DbUpdateException)
        {
            await transaction.RollbackAsync();

            return Conflict(new
            {
                message =
                    "These accounts could not be deleted because related " +
                    "records may depend on them. No deletion was completed."
            });
        }
        catch
        {
            await transaction.RollbackAsync();

            return StatusCode(500, new
            {
                message = "Deletion failed. Please try again."
            });
        }

        return Ok(new
        {
            message = $"{accounts.Count} account(s) permanently deleted.",
            deletedCount = accounts.Count
        });
    }

    // POST: /api/Admin/approve/5
    [Authorize(Roles = "admin")]
    [HttpPost("approve/{id:int}")]
    public async Task<IActionResult> ApproveAccount(int id)
    {
        var account = await _context.Users.FindAsync(id);

        if (account == null ||
            string.Equals(
                account.Role, "admin",
                StringComparison.OrdinalIgnoreCase))
        {
            return NotFound(new
            {
                message = "Account not found."
            });
        }

        if (!string.Equals(
                account.Status, "Pending",
                StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new
            {
                message = "This account is not pending approval."
            });
        }

        account.Status = "Approved";
        await _context.SaveChangesAsync();

        return Ok(new
        {
            message = "Account approved successfully."
        });
    }

    // POST: /api/Admin/reject/5
    [Authorize(Roles = "admin")]
    [HttpPost("reject/{id:int}")]
    public async Task<IActionResult> RejectAccount(int id)
    {
        var account = await _context.Users.FindAsync(id);

        if (account == null ||
            string.Equals(
                account.Role, "admin",
                StringComparison.OrdinalIgnoreCase))
        {
            return NotFound(new
            {
                message = "Account not found."
            });
        }

        if (!string.Equals(
                account.Status, "Pending",
                StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new
            {
                message = "This account is not pending approval."
            });
        }

        account.Status = "Rejected";
        await _context.SaveChangesAsync();

        return Ok(new
        {
            message = "Account rejected successfully."
        });
    }

    // POST: /api/Admin/logout
    [Authorize(Roles = "admin")]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(
            CookieAuthenticationDefaults.AuthenticationScheme);

        return Ok(new
        {
            message = "Administrator logged out."
        });
    }
}

public class AdminLoginRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class DeleteUsersRequest
{
    public List<int> Ids { get; set; } = new();
}