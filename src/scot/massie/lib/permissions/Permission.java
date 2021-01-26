package scot.massie.lib.permissions;

public final class Permission
{
    public Permission(boolean isNegation, boolean isWildcard)
    { this(isNegation, isWildcard, null); }

    public Permission(boolean isNegation, boolean isWildcard, String argument)
    {
        this.isNegation = isNegation;
        this.isWildcard = isWildcard;
        this.argument = argument;
    }

    boolean isNegation;
    boolean isWildcard;
    String argument;

    public boolean isNegation()
    { return isNegation; }

    public boolean isWildcard()
    { return isWildcard; }

    public boolean hasArg()
    { return argument != null; }

    public String getArg()
    { return argument; }

    public String getArgOr(String defaultVal)
    { return argument != null ? argument : defaultVal; }
}
