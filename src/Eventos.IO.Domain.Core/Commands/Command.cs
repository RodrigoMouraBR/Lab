using System;
using Eventos.IO.Domain.Core.Events;

namespace Eventos.IO.Domain.Core.Commands
{
    public class Command : Message
    {
        public DateTime Timestamp { get; private set; }

        public Command()
        {
            Timestamp = DateTime.Now;
        }
    }
}