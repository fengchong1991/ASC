using ASC.Tests.TestUtilities;
using ASC.Utilities;
using ASC.Web.Configuration;
using ASC.Web.Controllers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using System;
using Xunit;

namespace ASC.Tests
{
    public class HomeControllerTests
    {

        private readonly Mock<IOptions<ApplicationSettings>> optionsMock;
        private readonly Mock<HttpContext> mockHttpContext;


        public HomeControllerTests()
        {
            // Create an instance of Mock IOptions
            optionsMock = new Mock<IOptions<ApplicationSettings>>();
            mockHttpContext = new Mock<HttpContext>();

            // Set IOptions<> Values property to return ApplicationSettings object
            optionsMock.Setup(ap => ap.Value).Returns(new ApplicationSettings
            {
                ApplicationTitle = "ASC"
            });

            mockHttpContext.Setup(p => p.Session).Returns(new FakeSession());
        }

        [Fact]
        public void HomeController_Index_View_Test()
        {
            var controller = new HomeController(optionsMock.Object);
            controller.ControllerContext.HttpContext = mockHttpContext.Object;
            Assert.IsAssignableFrom<ViewResult>(controller.Index());
        }

        [Fact]
        public void HomeController_Index_NoMdel_Test()
        {
            var controller = new HomeController(optionsMock.Object);
            controller.ControllerContext.HttpContext = mockHttpContext.Object;
            // Assert Model for Null
            Assert.Null((controller.Index() as ViewResult).ViewData.Model);
        }

        [Fact]
        public void HomeController_Index_Validation_Test()
        {
            var controller = new HomeController(optionsMock.Object);

            controller.ControllerContext.HttpContext = mockHttpContext.Object;
            // Assert ModelState Error Count to 0
            Assert.Equal(0, (controller.Index() as ViewResult).ViewData.ModelState.ErrorCount);
        }

        [Fact]
        public void HomeController_Index_Session_Test()
        {
            var controller = new HomeController(optionsMock.Object);
            controller.ControllerContext.HttpContext = mockHttpContext.Object;

            controller.Index();

            Assert.NotNull(controller.HttpContext.Session.GetSession<ApplicationSettings>("Test"));
        }
    }
}
