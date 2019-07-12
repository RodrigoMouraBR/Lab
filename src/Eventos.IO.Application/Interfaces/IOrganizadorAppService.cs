using System;
using Eventos.IO.Application.ViewModels;

namespace Eventos.IO.Application.Interfaces
{
    public interface IOrganizadorAppService : IDisposable
    {
        void Registrar(OrganizadorViewModel organizadorViewModel);
    }
}