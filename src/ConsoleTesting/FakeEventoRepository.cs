using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using Eventos.IO.Domain.Eventos;
using Eventos.IO.Domain.Eventos.Repository;

namespace ConsoleTesting
{
    public class FakeEventoRepository : IEventoRepository
    {
        public void Add(Evento obj)
        {
            //
        }

        public void Dispose()
        {
            //
        }

        public IEnumerable<Evento> Find(Expression<Func<Evento, bool>> predicate)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<Evento> GetAll()
        {
            throw new NotImplementedException();
        }

        public Evento GetById(Guid id)
        {
            return new Evento("Fake", DateTime.Now, DateTime.Now, true, 0, true, "Empresa");
        }

        public void Remove(Guid id)
        {
            //
        }

        public int SaveChanges()
        {
            throw new NotImplementedException();
        }

        public void Update(Evento obj)
        {
            //
        }
    }
}