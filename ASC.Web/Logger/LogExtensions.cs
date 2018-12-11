using ASC.Business.Interfaces;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Logger
{
    public class AzureStorageLogger : ILogger
    {
        private readonly string _categoryName;
        private readonly Func<string, LogLevel, bool> _filter;
        private readonly ILogDataOperations _logOperations;

        public AzureStorageLogger(string categoryName, Func<string, LogLevel, bool> filter, ILogDataOperations logDataOperations)
        {
            _categoryName = categoryName;
            _filter = filter;
            _logOperations = logDataOperations;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            return null;
        }

        /// <summary>
        /// Check wheteher logging is enabled for a given log level
        /// </summary>
        /// <param name="logLevel"></param>
        /// <returns></returns>
        public bool IsEnabled(LogLevel logLevel)
        {
            return (_filter == null || _filter(_categoryName, logLevel));
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            if (!IsEnabled(logLevel)){
                return;
            }

            if (exception == null)
            {
                _logOperations.CreateLogAsync(logLevel.ToString(), formatter(state, exception));
            }
            else
            {
                _logOperations.CreateExceptionLogAsync(eventId.Name, exception.Message, exception.StackTrace);
            }
        }
    }


    /// <summary>
    /// Create the instance of ILogger types
    /// <see cref="AzureStorageLogger"></cref>
    /// </summary>
    public class AzureStorageLoggerProvider : ILoggerProvider
    {
        private readonly Func<string, LogLevel, bool> _filter;
        private readonly ILogDataOperations _logDataOperations;
        
        public AzureStorageLoggerProvider(Func<string, LogLevel, bool> filter, ILogDataOperations logDataOperations)
        {
            _logDataOperations = logDataOperations;
            _filter = filter;
        }
             
        public ILogger CreateLogger(string categoryName)
        {
            return new AzureStorageLogger(categoryName, _filter, _logDataOperations);
        }

        public void Dispose()
        {
        }
    }

    public static class EmailLoggerExtensions
    {
        public static ILoggerFactory AddAzureTableStorageLog(this ILoggerFactory factory, ILogDataOperations logOperations, Func<string, LogLevel, bool> filter = null)
        {
            factory.AddProvider(new AzureStorageLoggerProvider(filter, logOperations));
            return factory;
        }
    }
}
