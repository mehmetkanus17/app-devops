// SimpleTodoApp/Data/ApplicationDbContext.cs
using Microsoft.EntityFrameworkCore;
using SimpleTodoApp.Models;

namespace SimpleTodoApp.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<TodoItem> TodoItems { get; set; } = default!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<TodoItem>().HasKey(t => t.Id); // Id'yi PK olarak belirt
            // İsterseniz burada diğer model konfigürasyonlarını yapabilirsiniz
        }
    }
}