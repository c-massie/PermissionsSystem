package scot.massie.lib.permissions;

import java.util.List;

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

    public String toString(List<String> path)
    { return toString(String.join(".", path));  }

    public String toString(String[] path)
    { return toString(String.join(".", path)); }

    public String toString(String pathAsString)
    {
        String result = pathAsString;

        if(isNegation)
            result = "-" + result;

        if(isWildcard)
            result += ".*";

        if(argument != null)
            result = result + ": " + argument;

        return result;
    }

    @Override
    public String toString()
    { return toString("(path)"); }
}
