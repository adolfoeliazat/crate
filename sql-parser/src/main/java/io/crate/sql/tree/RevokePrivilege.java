package io.crate.sql.tree;

import java.util.List;
import java.util.Objects;

public class RevokePrivilege extends Statement{

    private final List<Privilege> privileges;
    private final List<String> userNames;

    public RevokePrivilege(List<String> userNames,
                          boolean allPrivileges,
                          List<Privilege> privileges) {

        if (allPrivileges){
            this.privileges = Privilege.getALL();
        } else {
            this.privileges = privileges;
        }
        this.userNames = userNames;
    }

    public List<Privilege> privileges(){
        return privileges;
    }

    public List<String> userNames(){
        return userNames;
    }


    @Override
    public <R, C> R accept(AstVisitor<R, C> visitor, C context) {
        return visitor.visitRevokePrivilege(this, context);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final RevokePrivilege that = (RevokePrivilege) o;
        return Objects.equals(this.privileges, that.privileges)
            && Objects.equals(this.userNames, that.userNames);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privileges, userNames);
    }

    @Override
    public String toString() {
        return "RevokePrivilege{" +
            "privileges=" + privileges +
            ", userNames=" + userNames +
            '}';
    }
}
