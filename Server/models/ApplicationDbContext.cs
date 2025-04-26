using System.Data.Entity;
using Server.Models;

namespace Server.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext()
            : base(@"Data Source=(LocalDB)\MSSQLLocalDB;AttachDbFilename=|DataDirectory|\MessagerDB.mdf;Integrated Security=True")
        {
            // Configuração
            this.Configuration.LazyLoadingEnabled = true;
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Room> Rooms { get; set; }
        public DbSet<Message> Messages { get; set; }
        public DbSet<UserRoom> UserRooms { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            // Configurações de relacionamentos específicos, se necessário

            // Configuração da relação entre User e Message
            modelBuilder.Entity<User>()
                .HasMany(u => u.Messages)
                .WithRequired(m => m.Sender)
                .HasForeignKey(m => m.SenderId);

            // Configuração da relação entre Room e Message
            modelBuilder.Entity<Room>()
                .HasMany(r => r.Messages)
                .WithRequired(m => m.Room)
                .HasForeignKey(m => m.RoomId);

            // Configuração da relação entre User e UserRoom
            modelBuilder.Entity<User>()
                .HasMany(u => u.UserRooms)
                .WithRequired(ur => ur.User)
                .HasForeignKey(ur => ur.UserId);

            // Configuração da relação entre Room e UserRoom
            modelBuilder.Entity<Room>()
                .HasMany(r => r.UserRooms)
                .WithRequired(ur => ur.Room)
                .HasForeignKey(ur => ur.RoomId);

            base.OnModelCreating(modelBuilder);
        }
    }
}