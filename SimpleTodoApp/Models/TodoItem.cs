// SimpleTodoApp/Models/TodoItem.cs
namespace SimpleTodoApp.Models
{
    public class TodoItem
    {
        public int Id { get; set; } // Primary Key
        public string Title { get; set; } = string.Empty; // Yapılacak işin başlığı
        public bool IsCompleted { get; set; } // Tamamlandı mı?
    }
}