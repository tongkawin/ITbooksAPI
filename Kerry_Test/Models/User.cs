namespace Kerry_Test
{
    public class User
    {
        public string Fullname { get; set; } = string.Empty;    
        public string Username { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }

    }
}
