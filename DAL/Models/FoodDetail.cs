using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DAL.Models
{
    public class FoodDetail
    {
        [Key]
        public Guid FoodDetailId { get; set; }

        [Required]
        public Guid FoodId { get; set; }
        [ForeignKey("FoodId")]
        public virtual Food? Food { get; set; }

        public int Calo { get; set; } 

        public string ThanhPhan { get; set; } 

        public int ThoiGianChuanBi { get; set; } 

        public bool Chay { get; set; } // Có phải món chay không?
    }
}
