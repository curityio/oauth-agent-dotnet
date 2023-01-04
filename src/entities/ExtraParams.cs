namespace IO.Curity.OAuthAgent.Entities
{
    public class ExtraParams
    {
        public string Key { get; private set; }

        public string Value { get; private set; }
        
        public ExtraParams(string key, string value)
        {
            this.Key = key;
            this.Value = value;
        }
    }
}
