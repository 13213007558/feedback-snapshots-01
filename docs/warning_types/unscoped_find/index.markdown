Unscoped `find` (and related methods) are a form of [Direct Object Reference](https://www.owasp.org/index.php/Top_10_2013-A4_Insecure_Direct_Object_References). Models which belong to another model should typically be accessed via a scoped query.

For example, if an `Account` belongs to a `User`, then this may be an unsafe unscoped find:

    Account.find(params[:id])

Depending on the action, this could allow an attacker to access any account they wish.

Instead, it should be scoped to the currently logged-in user:

    current_user = User.find(session[:user_id])
    current_user.accounts.find(params[:id])

## Owner association tracking

Brakeman does not assume that a variable named `current_account` is
authorized, and it does not treat every `belongs_to` as an authorization
boundary. To follow an owner association from the accessor used by the
controller to the final query, provide an explicit mapping in the
configuration file:

    :unscoped_find_owners:
      :current_account:
        :model: Account
        :associations:
          :orders: Order

With this mapping, Brakeman follows `current_account.orders` through the
relation and reports when the owner restriction is removed:

    current_account.orders.find(params[:id])              # still scoped
    current_account.orders.where(active: true).find(...)  # still scoped
    current_account.orders.unscoped.find(params[:id])     # scope removed
    Order.find(params[:id])                               # scope lost

The warning points at the step which removed the constraint (for example
`unscoped`), and the reported user input is the external ID from the final
`find` call.

Brakeman distinguishes three outcomes:

* **Still scoped**: the relation is restricted on the owner association and
  only adds conditions (`where`, `joins`, `order`, ...).
* **Scope removed or lost**: `unscoped`, `unscope(:where)`, `except(:where)`,
  `rewhere`, or recreating the relation from the model (`Order.find(...)`).
* **Cannot prove**: the relation is combined with an untrusted source
(`merge`/`or`) or reached through something other than the configured
accessor (for example `Account.find(session[:id]).orders`).

Anything that cannot be proven is reported so it can be reviewed. Other
relation methods not understood by this check are also treated as
unverifiable rather than silently assumed to be safe.

Note the mapping describes ownership, not authorization. An owner
association does not guarantee that the caller may access the record; it
only ties the lookup to that owner.
