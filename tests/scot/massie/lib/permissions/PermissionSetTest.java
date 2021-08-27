package scot.massie.lib.permissions;

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.*;

class PermissionSetTest
{
    /*

    Tests assume that set works as expected, except for the tests for set itself

    Where overloads of String, List<String>, and String... exist, only test the List<String> overload. The other two
    overloads point to the List<String> overload, and the String overload should work where splitPath works as expected.

    static string manipulation methods
        splitPath
            empty string
            string with no separators
            string with multiple separators
        applyPermissionToPathStringWithoutArg
            permission negates
            permission
        applyPermissionToPathString
            permission, no arg
            permission, single line arg
            permission, multi-line arg
            permission negates, no arg
            permission negates, single-line arg
            permission negates, multi-line arg

    accessors
        tests as a whole
            hasAny
                empty
                has exact permission
                has descendant permission
            isEmpty
                empty
                has exact permission
                has descendant permission
        getters
            getMostRelevantPermission
                empty
                has no relevant permissions
                has permission exactly in descendant tree
                has permission exactly in exact tree
                has permission that covers in descendant tree
                has permission that covers in exact tree
            getPermission
                doesn't need to be tested, covered by getMostRelevantPermission
        test permissions
            hasPermission
                doesn't need to be tested, covered by getMostRelevantPermission
            hasPermissionOrAnyUnder
                empty
                has no permissions under
                has permission exactly in descendant tree
                has permission exactly in exact tree
                has covered permission in descendant tree
                has covered permission in exact tree
            hasPermissionOrAnyUnderWhere
                empty
                has no permissions under
                has permission exactly in descendant tree
                has permission exactly in descendant tree failing predicate
                has permission exactly in exact tree
                has permission exactly in exact tree failing predicate
                has covered permission in descendant tree
                has covered permission in descendant tree failing predicate
                has covered permission in exact tree
                has covered permission in exact tree failing predicate
            hasPermissionExactly
                simple function, doesn't need to be tested
            negatesPermission
                doesn't need to be tested, covered by getMostRelevantPermission
            negatesPermissionExactly
                simple function, doesn't need to be tested
        conversion to savestrings
            getPermissionsAsStrings
                empty
                single permission, no args
                single permission, single-line arg
                single permission, multi-line arg
                multiple permissions, no args
                multiple permissions, single-line args
                multiple permissions, multi-line args
            toSaveString
                empty
                single permission, no args
                single permission, single-line arg
                single permission, multi-line arg
                multiple permissions, no args
                multiple permissions, single-line args
                multiple permissions, multi-line args

    mutators
        set
            permission
            permission with single-line arg
            permission with multi-line arg
            wildcard permission
            negating permission
            permission with wildcard in illegal place
            permission with negation in illegal place
        setWhileDeIndenting
            permission without arg
            permission with single-line arg
            permission with multi-line arg
        remove
            empty
            no matching permission
            matching permission
            matching permission, but wrong state of negation
            matching permission, but wrong use of wildcard
            matching permission, also has same permission wildcarded that should not be removed
        clear
            simple function, doesn't need to be tested

     */
}