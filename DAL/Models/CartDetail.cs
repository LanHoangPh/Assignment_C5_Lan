using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DAL.Models
{
    public class CartDetail
    {

        [Key]
        public Guid CartDetailId { get; set; }

        [Required]
        public Guid? CartId { get; set; }
        [ForeignKey("CartId")]
        public virtual Cart? Cart { get; set; }

        [Required]
        public Guid? FoodId { get; set; }
        // Mối quan hệ n - 1 với Food
        [ForeignKey("FoodId")]
        public virtual Food? Food { get; set; }

        [Required]
        public int SoLuong { get; set; }
    }
}
