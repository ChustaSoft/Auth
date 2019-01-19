﻿using System;

namespace ChustaSoft.Tools.Authorization.Models
{
    [Serializable]
    public class Credentials
    {

        public string Username { get; set; }

        public string Email { get; set; }

        public string Password { get; set; }

    }
}
