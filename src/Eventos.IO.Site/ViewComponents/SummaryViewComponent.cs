using System.Threading.Tasks;
using Eventos.IO.Domain.Core.Notifications;
using Microsoft.AspNetCore.Mvc;

namespace Eventos.IO.Site.ViewComponents
{
    public class SummaryViewComponent : ViewComponent
    {
        private readonly IDomainNotificationHandler<DomainNotification> _notifications;

        public SummaryViewComponent(IDomainNotificationHandler<DomainNotification> notifications)
        {
            _notifications = notifications;
        }

        public async Task<IViewComponentResult> InvokeAsync()
        {
            var notificacoes = await Task.FromResult(_notifications.GetNotifications());
            notificacoes.ForEach(c=> ViewData.ModelState.AddModelError(string.Empty, c.Value));

            return View();
        }
    }
}