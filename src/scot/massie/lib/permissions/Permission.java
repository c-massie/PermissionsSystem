package scot.massie.lib.permissions;

import java.util.List;
import java.util.Objects;

public final class Permission
{
    public Permission(boolean isNegation, boolean isWildcard)
    { this(isNegation, isWildcard, null); }

    public Permission(boolean isNegation, boolean isWildcard, String argument)
    { this(!isWildcard && !isNegation, !isWildcard && isNegation, !isNegation, isNegation, argument); }

    Permission(boolean includesExact,
               boolean negatesExact,
               boolean includesDescendants,
               boolean negatesDescendants,
               String argument)
    {
        this.includesExact = includesExact;
        this.negatesExact = negatesExact;
        this.includesDescendants = includesDescendants;
        this.negatesDescendants = negatesDescendants;
        this.argument = argument;
        this.argumentForDescendants = argument;
    }

    private final boolean includesExact;
    private final boolean negatesExact;
    private final boolean includesDescendants;
    private final boolean negatesDescendants;
    private final String  argument;
    private final String  argumentForDescendants;

    public boolean includesExact()
    { return includesExact; }

    public boolean negatesExact()
    { return negatesExact; }

    public boolean coversExact()
    { return includesExact || negatesExact; }

    public boolean includesDescendants()
    { return includesDescendants; }

    public boolean negatesDescendants()
    { return negatesDescendants; }

    public boolean coversDescendants()
    { return includesDescendants || negatesDescendants; }

    public boolean isValid()
    { return !(includesExact && negatesExact) && !(includesDescendants && negatesDescendants); }

    // If this permission applies opposing rules for this level and its descendants.
    public boolean isHypocritical()
    { return (includesExact && negatesDescendants) || (negatesExact && includesDescendants); }

    public boolean exactAndDescendantsAreSame()
    {
        return (includesExact == includesDescendants)
            && (negatesExact == negatesDescendants)
            && (Objects.equals(argument, argumentForDescendants));
    }

    public boolean hasArg()
    { return argument != null; }

    public boolean hasArgForDescendants()
    { return argumentForDescendants != null; }

    public String getArg()
    { return argument; }

    public String getArgForDescendants()
    { return argumentForDescendants; }

    public String getArgOr(String defaultVal)
    { return argument != null ? argument : defaultVal; }

    public String getArgForDescendantsOr(String defaultVal)
    { return argumentForDescendants; }

    public boolean hasSameArgForExactAndDescendants()
    { return Objects.equals(argument, argumentForDescendants); }
}
