using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DAL.Models
{
    public class Food
    {
        [Key]
        public Guid FoodId { get; set; }

        [Required, MaxLength(100)]
        public string TenMon { get; set; } 

        public string MoTa { get; set; } 

        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal Gia { get; set; } 

        [Required]
        public int SoLuong { get; set; } 

        public string? ImageUrl { get; set; } 

        public int TrangThai { get; set; } // 1 = Đang bán, 2 = Hết hàng, 3 = Ngừng kinh doanh

        // Liên kết với bảng FoodCategory (Phân loại món ăn)
        [Required]
        public Guid? CategoryId { get; set; }
        [ForeignKey("CategoryId")]
        public virtual FoodCategory? Category { get; set; }

        // Liên kết 1-1 với FoodDetail
        public virtual FoodDetail? FoodDetail { get; set; }

        // Mối quan hệ 1-n với CartDetail (Món ăn trong giỏ hàng)
        public virtual ICollection<CartDetail> CartDetails { get; set; } = new List<CartDetail>();

        // Mối quan hệ 1-n với OrderDetail (Món ăn trong hóa đơn)
        public virtual ICollection<OrderDetail> OrderDetails { get; set; } = new List<OrderDetail>();
    }
}
