package scot.massie.lib.permissions;

import scot.massie.lib.collections.tree.Tree;
import scot.massie.lib.collections.tree.RecursiveTree;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

public final class PermissionSet
{
    private static final class PermissionWithPath
    {
        public PermissionWithPath(List<String> path, Permission perm)
        {
            this.path = path;
            this.permission = perm;
        }

        private final List<String> path;
        private final Permission permission;

        public List<String> getPath()
        { return path; }

        public Permission getPermission()
        { return permission; }
    }

    public static final class PermissionCoverage
    {
        public PermissionCoverage(boolean hasPermission, boolean negatesPermission)
        {
            this.hasPermission = hasPermission;
            this.negatesPermission = negatesPermission;
        }

        private final boolean hasPermission;
        private final boolean negatesPermission;

        public boolean hasPermission()
        { return hasPermission; }

        public boolean negatesPermission()
        { return negatesPermission; }

        public boolean coversPermission()
        { return hasPermission || negatesPermission; }
    }

    Tree<String, Permission> permissionTree = new RecursiveTree<>();

    protected String[] splitPath(String permissionPath)
    { return permissionPath.split("\\."); }

    public void add(String permissionAsString) throws ParseException
    {
        boolean isNegation = false;
        boolean isWildcard = false;
        String[] parts = permissionAsString.split(":", 2);
        String permWithoutArg = parts[0].trim();
        String permArg = parts.length > 1 ? parts[1].trim() : null;

        if(permWithoutArg.startsWith("-"))
        {
            isNegation = true;
            permWithoutArg = permWithoutArg.substring(1);
        }

        if(permWithoutArg.endsWith(".*"))
        {
            isWildcard = true;
            permWithoutArg = permWithoutArg.substring(0, permWithoutArg.length() - 2);
        }

        if(permWithoutArg.contains("*"))
            throw new ParseException
            (
                "Permissions cannot be arbitrarily wildcarded: " + permissionAsString,
                permissionAsString.indexOf("*")
            );

        if(permWithoutArg.contains("-"))
            throw new ParseException
            (
                "Permission negations must be at the start of the permission: " + permissionAsString,
                permissionAsString.indexOf("-", isNegation ? 1 : 0)
            );

        permissionTree.setAt(new Permission(isNegation, isWildcard, permArg), splitPath(permWithoutArg));
    }

    public void remove(String permissionAsString)
    {
        permissionAsString = permissionAsString.trim();

        if(permissionAsString.contains(":"))
            permissionAsString = permissionAsString.substring(0, permissionAsString.indexOf(":")).trim();

        if(permissionAsString.startsWith("-"))
            permissionAsString = permissionAsString.substring(1).trim();

        if(permissionAsString.endsWith(".*"))
            permissionAsString = permissionAsString.substring(0, permissionAsString.length() - 2).trim();

        permissionTree.clearAt(splitPath(permissionAsString));
    }

    private PermissionWithPath getMostRelevantPermission(List<String> permissionPath)
    {
        List<Tree.Entry<String, Permission>> relevantPerms = permissionTree.getEntriesAlong(permissionPath);

        if(relevantPerms.isEmpty())
            return null;

        // mrp = most relevant permission
        Tree.Entry<String, Permission> mrpWithPath = relevantPerms.get(relevantPerms.size() - 1);

        if((mrpWithPath.getPath().size() == permissionPath.size()) && (!mrpWithPath.getItem().coversExact()))
        {
            if(relevantPerms.size() <= 1)
                return null;

            mrpWithPath = relevantPerms.get(relevantPerms.size() - 2);
        }

        return new PermissionWithPath(mrpWithPath.getPath().getNodes(), mrpWithPath.getItem());
    }

    public boolean hasPermission(String permissionPath)
    { return hasPermission(Arrays.asList(splitPath(permissionPath))); }

    public boolean hasPermission(List<String> permissionPath)
    {
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);
        return (mrp != null) && ((mrp.path.size() == permissionPath.size()) ? mrp.permission.includesExact()
                                                                            : mrp.permission.includesDescendants());
    }

    public boolean hasPermission(String... permissionPath)
    { return hasPermission(Arrays.asList(permissionPath)); }

    public boolean hasPermissionExactly(String permissionPath)
    { return hasPermissionExactly(splitPath(permissionPath)); }

    public boolean hasPermissionExactly(List<String> permissionPath)
    { return permissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.includesExact()); }

    public boolean hasPermissionExactly(String... permissionPath)
    { return permissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.includesExact()); }

    public boolean negatesPermission(String permissionPath)
    { return negatesPermission(Arrays.asList(splitPath(permissionPath))); }

    public boolean negatesPermission(List<String> permissionPath)
    {
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);
        return (mrp != null) && ((mrp.path.size() == permissionPath.size()) ? (mrp.permission.negatesExact())
                                                                            : (mrp.permission.negatesDescendants()));
    }

    public boolean negatesPermission(String... permissionPath)
    { return negatesPermission(Arrays.asList(permissionPath)); }

    public boolean negatesPermissionExactly(String permissionPath)
    { return negatesPermissionExactly(splitPath(permissionPath)); }

    public boolean negatesPermissionExactly(List<String> permissionPath)
    { return permissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.negatesExact()); }

    public boolean negatesPermissionExactly(String... permissionPath)
    { return permissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.negatesExact()); }

    public boolean coversPermission(String permissionPath)
    { return coversPermission(Arrays.asList(splitPath(permissionPath))); }

    public boolean coversPermission(List<String> permissionPath)
    {
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);
        return (mrp != null) && ((mrp.path.size() == permissionPath.size()) ? mrp.permission.coversExact()
                                                                            : mrp.permission.coversDescendants());
    }

    public boolean coversPermission(String... permissionPath)
    { return coversPermission(Arrays.asList(permissionPath)); }

    public boolean coversPermissionExactly(String permissionPath)
    { return coversPermissionExactly(Arrays.asList(splitPath(permissionPath))); }

    public boolean coversPermissionExactly(List<String> permissionPath)
    { return permissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.coversExact()); }

    public boolean coversPermissionExactly(String... permissionPath)
    { return permissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.coversExact()); }

    public PermissionCoverage getCoverageOf(String permissionPath)
    { return getCoverageOf(Arrays.asList(splitPath(permissionPath))); }

    public PermissionCoverage getCoverageOf(List<String> permissionPath)
    {
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return new PermissionCoverage(false, false);

        boolean isForExact = mrp.path.size() == permissionPath.size();
        boolean has     = isForExact ? mrp.permission.includesExact() : mrp.permission.includesDescendants();
        boolean negates = isForExact ? mrp.permission.negatesExact()  : mrp.permission.negatesDescendants();
        return new PermissionCoverage(has, negates);
    }

    public PermissionCoverage getCoverageOf(String... permissionPath)
    { return getCoverageOf(Arrays.asList(permissionPath)); }
}
