using System;
using Eventos.IO.Domain.Core.Events;

namespace Eventos.IO.Domain.Organizadores.Events
{
    public class OrganizadorEventHandler :
        IHandler<OrganizadorRegistradoEvent>
    {
        public void Handle(OrganizadorRegistradoEvent message)
        {
            // TODO: Enviar um email?
        }
    }
}