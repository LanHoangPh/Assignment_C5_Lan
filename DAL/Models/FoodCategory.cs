using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DAL.Models
{
    public class FoodCategory
    {
        [Key]
        public Guid CategoryId { get; set; }

        [Required, MaxLength(50)]
        public string TenLoai { get; set; } // VD: Món chính, Đồ uống, Tráng miệng

        public string? MoTa { get; set; }

        // Mối quan hệ 1 - n với Food
        public virtual ICollection<Food> Foods { get; set; } = new List<Food>();
    }
}
