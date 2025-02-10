using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using DAL.Models;
using DAL.Server;

namespace FoodWeb.Controllers
{
    public class FoodDetailsController : Controller
    {
        private readonly ApplicationDbContext _context;

        public FoodDetailsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: FoodDetails
        public async Task<IActionResult> Index()
        {
            var applicationDbContext = _context.FoodDetails.Include(f => f.Food);
            return View(await applicationDbContext.ToListAsync());
        }

        // GET: FoodDetails/Details/5
        public async Task<IActionResult> Details(Guid? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var foodDetail = await _context.FoodDetails
                .Include(f => f.Food)
                .FirstOrDefaultAsync(m => m.FoodDetailId == id);
            if (foodDetail == null)
            {
                return NotFound();
            }

            return View(foodDetail);
        }

        // GET: FoodDetails/Create
        public IActionResult Create()
        {
            ViewData["FoodId"] = new SelectList(_context.Foods, "FoodId", "MoTa");
            return View();
        }

        // POST: FoodDetails/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("FoodDetailId,FoodId,Calo,ThanhPhan,ThoiGianChuanBi,Chay")] FoodDetail foodDetail)
        {
            if (ModelState.IsValid)
            {
                foodDetail.FoodDetailId = Guid.NewGuid();
                _context.Add(foodDetail);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            ViewData["FoodId"] = new SelectList(_context.Foods, "FoodId", "MoTa", foodDetail.FoodId);
            return View(foodDetail);
        }

        // GET: FoodDetails/Edit/5
        public async Task<IActionResult> Edit(Guid? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var foodDetail = await _context.FoodDetails.FindAsync(id);
            if (foodDetail == null)
            {
                return NotFound();
            }
            ViewData["FoodId"] = new SelectList(_context.Foods, "FoodId", "MoTa", foodDetail.FoodId);
            return View(foodDetail);
        }

        // POST: FoodDetails/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(Guid id, [Bind("FoodDetailId,FoodId,Calo,ThanhPhan,ThoiGianChuanBi,Chay")] FoodDetail foodDetail)
        {
            if (id != foodDetail.FoodDetailId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(foodDetail);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!FoodDetailExists(foodDetail.FoodDetailId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            ViewData["FoodId"] = new SelectList(_context.Foods, "FoodId", "MoTa", foodDetail.FoodId);
            return View(foodDetail);
        }

        // GET: FoodDetails/Delete/5
        public async Task<IActionResult> Delete(Guid? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var foodDetail = await _context.FoodDetails
                .Include(f => f.Food)
                .FirstOrDefaultAsync(m => m.FoodDetailId == id);
            if (foodDetail == null)
            {
                return NotFound();
            }

            return View(foodDetail);
        }

        // POST: FoodDetails/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(Guid id)
        {
            var foodDetail = await _context.FoodDetails.FindAsync(id);
            if (foodDetail != null)
            {
                _context.FoodDetails.Remove(foodDetail);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool FoodDetailExists(Guid id)
        {
            return _context.FoodDetails.Any(e => e.FoodDetailId == id);
        }
    }
}
