using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Server.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(50)]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }

        // Navegação para mensagens
        public virtual ICollection<Message> Messages { get; set; }

        // Navegação para salas
        public virtual ICollection<UserRoom> UserRooms { get; set; }
    }
}