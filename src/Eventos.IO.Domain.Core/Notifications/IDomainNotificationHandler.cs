using System.Collections.Generic;
using Eventos.IO.Domain.Core.Events;

namespace Eventos.IO.Domain.Core.Notifications
{
    public interface IDomainNotificationHandler<T> : IHandler<T> where T : Message
    {
        bool HasNotifications();
        List<T> GetNotifications();
    }
}