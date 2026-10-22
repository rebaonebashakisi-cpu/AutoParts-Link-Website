using AutoParts_Link_Website.Models;
using Microsoft.EntityFrameworkCore;

namespace AutoParts_Link_Website.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();

    public DbSet<PartListing> PartListings => Set<PartListing>();
}