using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Server.Models
{
    public class Message
    {
        [Key]
        public int Id { get; set; }

        public string Content { get; set; }

        public string EncryptedContent { get; set; }

        public DateTime SentAt { get; set; } = DateTime.Now;

        // Chave estrangeira para o remetente
        [ForeignKey("Sender")]
        public int SenderId { get; set; }
        public virtual User Sender { get; set; }

        // Chave estrangeira para a sala
        [ForeignKey("Room")]
        public int RoomId { get; set; }
        public virtual Room Room { get; set; }
    }
}