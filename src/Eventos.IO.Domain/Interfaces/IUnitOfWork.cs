using System;
using Eventos.IO.Domain.Core.Commands;

namespace Eventos.IO.Domain.Interfaces
{
    public interface IUnitOfWork : IDisposable
    {
        CommandResponse Commit();
    }
}