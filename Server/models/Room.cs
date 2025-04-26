using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Server.Models
{
    public class Room
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(50)]
        public string Name { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now;

        // Navegação para mensagens
        public virtual ICollection<Message> Messages { get; set; }

        // Navegação para usuários
        public virtual ICollection<UserRoom> UserRooms { get; set; }
    }
}