namespace AutoParts_Link_Website.Models;

public class PartListing
{
    public int Id { get; set; }

    public string Title { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string? CarMake { get; set; }

    public string? CarModel { get; set; }

    public int? CarYear { get; set; }

    public decimal Price { get; set; }

    public string? ImageUrl { get; set; }

    public string Status { get; set; } = "Pending";

    public int SellerId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}