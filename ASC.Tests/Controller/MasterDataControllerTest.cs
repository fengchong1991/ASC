using ASC.Business.Interfaces;
using ASC.Models.Models;
using ASC.Tests.TestUtilities;
using ASC.Utilities;
using ASC.Web.Controllers;
using ASC.Web.Models.MappingProfile;
using ASC.Web.Models.MasterDataViewModels;
using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace ASC.Tests.Controller
{
    public class MasterDataControllerTest
    {
        private Mock<IMasterDataOperations> _masterDataOperations;
        private Mapper _autoMapper;
        private readonly Mock<HttpContext> _mockHttpContext;
        private MasterDataController _controller;

        public MasterDataControllerTest()
        {
            _masterDataOperations = new Mock<IMasterDataOperations>();
            _autoMapper = new Mapper(new MapperConfiguration(cfg => cfg.AddProfile(new MappingProfile())));
            _mockHttpContext = new Mock<HttpContext>();

            _mockHttpContext.Setup(p => p.Session).Returns(new FakeSession());
            _controller = new MasterDataController(_masterDataOperations.Object, _autoMapper);
        }

        [Fact]
        public async Task MasterKeysTest_ReturnsViewWithMasterKeys()
        {

            // Arrange
            var mockMasterKeysList = new List<MasterDataKey>()
            {
                new MasterDataKey()
                {
                    Name = "123"
                },
                new MasterDataKey()
                {
                    Name = "234"
                }
            };

            _masterDataOperations
                .Setup(op => op.GetAllMasterKeysAsync())
                .Returns(Task.FromResult(mockMasterKeysList));

            _controller.ControllerContext.HttpContext = _mockHttpContext.Object;

            // Act
            var result = await _controller.MasterKeys();

            // Assert
            var viewResult = Assert.IsType<ViewResult>(result);
            var model = Assert.IsType<MasterKeysViewModel>(viewResult.Model);
            Assert.Equal(2, model.MasterKeys.Count);
        }

        [Fact]
        public async Task MasterKeysTest_InvalidModel()
        {
            // Arrange
            var model = new MasterKeysViewModel();
            _controller.ModelState.AddModelError("", "TestError");
            _controller.ControllerContext.HttpContext = _mockHttpContext.Object;

            // Act
            var result = await _controller.MasterKeys(model);

            // Assert
            var viewResult = Assert.IsType<ViewResult>(result);
            Assert.Equal(model, viewResult.ViewData.Model);
            _masterDataOperations.Verify(repo => repo.UpdateMasterKeyAsync(null, null), Times.Never);
        }


        [Fact]
        public async Task MasterKeysTest_AddSuccessful()
        {
            // Arrange
            var model = new MasterKeysViewModel();
            model.MasterKeyInContext = new MasterDataKeyViewModel();

            byte[] vm = Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(new List<MasterDataKeyViewModel>()));

            _mockHttpContext
                .Setup(context => context.Session.TryGetValue("MasterKeys", out vm))
                .Returns(true);
            
            _controller.ControllerContext.HttpContext = _mockHttpContext.Object;

            // Act
            var result = await _controller.MasterKeys(model);

            // Assert
            var viewResult = Assert.IsType<RedirectToActionResult>(result);

            _masterDataOperations.Verify(repo => repo.InsertMasterKeyAsync(It.IsAny<MasterDataKey>()));
        }
    }
}
