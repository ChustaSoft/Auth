﻿using ChustaSoft.Tools.Authorization.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Authentication;


namespace ChustaSoft.Tools.Authorization.UnitTest.TestServices
{
    [TestClass]
    public class CredantialsUnitTest
    {

        #region Test Fields

        private static ICredentialsBusiness ServiceUnderTest;

        #endregion


        #region Test Initialization

        [TestInitialize]
        public void TestInitialization()
        {
            ServiceUnderTest = new CredentialsBusiness();
        }

        #endregion


        #region Test Cases

        [TestMethod]
        public void Given_UserWithPhone_When_ValidateCredentialsRequested_Then_LoginTypePhoneRetrived()
        {
            var credentials = new Credentials { Phone = "666999666", Password = "OK" };

            var typeRetrived = ServiceUnderTest.ValidateCredentials(credentials);

            Assert.AreEqual(typeRetrived, LoginType.PHONE);
        }

        [TestMethod]
        public void Given_UserWithMail_When_ValidateCredentialsRequested_Then_LoginTypeMailRetrived()
        {
            var credentials = new Credentials { Email = "test@mail.com", Password = "OK" };

            var typeRetrived = ServiceUnderTest.ValidateCredentials(credentials);

            Assert.AreEqual(typeRetrived, LoginType.MAIL);
        }

        [TestMethod]
        public void Given_UserWithCode_When_ValidateCredentialsRequested_Then_LoginTypeCodeRetrived()
        {
            var credentials = new Credentials { Username = "test", Password = "OK" };

            var typeRetrived = ServiceUnderTest.ValidateCredentials(credentials);

            Assert.AreEqual(typeRetrived, LoginType.USER);
        }

        [TestMethod]
        [ExpectedException(typeof(AuthenticationException))]
        public void Given_UserWithoutPassword_When_ValidateCredentialsRequested_Then_ExceptionThrown()
        {
            var credentials = new Credentials { Username = "test", Email = "test@mail.com" };

            ServiceUnderTest.ValidateCredentials(credentials);
        }

        [TestMethod]
        [ExpectedException(typeof(AuthenticationException))]
        public void Given_WrongUser_When_ValidateCredentialsRequested_Then_ExceptionThrown()
        {
            var credentials = new Credentials();

            ServiceUnderTest.ValidateCredentials(credentials);
        }

        #endregion

    }
}
