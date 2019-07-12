using System;
using Eventos.IO.Domain.Core.Events;

namespace Eventos.IO.Domain.Eventos.Events
{
    public class EventoEventHandler :
        IHandler<EventoRegistradoEvent>,
        IHandler<EventoAtualizadoEvent>,
        IHandler<EventoExcluidoEvent>,
        IHandler<EnderecoEventoAdicionadoEvent>,
        IHandler<EnderecoEventoAtualizadoEvent>
    {
        public void Handle(EventoRegistradoEvent message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Evento Registrado com sucesso");
        }

        public void Handle(EventoAtualizadoEvent message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Evento Atualizado com sucesso");
        }

        public void Handle(EventoExcluidoEvent message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Evento Excluido com sucesso");
        }

        public void Handle(EnderecoEventoAdicionadoEvent message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Endereco do evento adicionado com sucesso");
        }

        public void Handle(EnderecoEventoAtualizadoEvent message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Endereco do evento atualizado com sucesso");
        }
    }
}