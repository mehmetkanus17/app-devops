// SimpleTodoApp/Pages/Index.cshtml.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SimpleTodoApp.Data;
using SimpleTodoApp.Models;

namespace SimpleTodoApp.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ApplicationDbContext context, ILogger<IndexModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        public IList<TodoItem> TodoItems { get;set; } = default!;

        public async Task OnGetAsync()
        {
            TodoItems = await _context.TodoItems.OrderBy(t => t.IsCompleted).ThenBy(t => t.Id).ToListAsync();
        }

        public async Task<IActionResult> OnPostAddTodoAsync(string Title)
        {
            if (!ModelState.IsValid || string.IsNullOrWhiteSpace(Title))
            {
                return Page();
            }

            var todoItem = new TodoItem { Title = Title, IsCompleted = false };
            _context.TodoItems.Add(todoItem);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Added new todo item: {Title}", Title);

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostCompleteAsync(int id)
        {
            var todoItem = await _context.TodoItems.FindAsync(id);

            if (todoItem == null)
            {
                return NotFound();
            }

            todoItem.IsCompleted = !todoItem.IsCompleted; // Toggle completion status
            await _context.SaveChangesAsync();

            _logger.LogInformation("Toggled completion for todo item Id: {Id}", id);

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDeleteAsync(int id)
        {
            var todoItem = await _context.TodoItems.FindAsync(id);

            if (todoItem == null)
            {
                return NotFound();
            }

            _context.TodoItems.Remove(todoItem);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Deleted todo item Id: {Id}", id);

            return RedirectToPage();
        }
    }
}