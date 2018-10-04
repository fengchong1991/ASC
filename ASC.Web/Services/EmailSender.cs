using ASC.Web.Configuration;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Services
{

    public class EmailSender : IEmailSender
    {
        private IOptions<ApplicationSettings> _settings;

        public EmailSender(IOptions<ApplicationSettings> settings)
        {
            _settings = settings;
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress(_settings.Value.SMTPAccount));
            emailMessage.To.Add(new MailboxAddress(email));
            emailMessage.Subject = subject;
            emailMessage.Body = new TextPart("plain") { Text = message };

            using(var client = new SmtpClient())
            {
                await client.ConnectAsync(_settings.Value.SMTPServer, _settings.Value.SMTPPort, true);
                await client.AuthenticateAsync(_settings.Value.SMTPAccount, _settings.Value.SMTPPassword);
                await client.SendAsync(emailMessage);
                await client.DisconnectAsync(true);
            }
        }
    }
}
