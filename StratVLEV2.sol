// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "./helpers/ERC20.sol";

import "./libraries/Address.sol";

import "./libraries/SafeERC20.sol";

import "./helpers/Ownable.sol";

import "./helpers/ReentrancyGuard.sol";

import "./helpers/Pausable.sol";

import "./interfaces/IPancakeRouter01.sol";

import "./interfaces/IPancakeRouter02.sol";

interface IVenusDistribution {
    function claimVenus(address holder) external;

    function enterMarkets(address[] memory _vtokens) external;

    function exitMarket(address _vtoken) external;

    function getAssetsIn(address account)
        external
        view
        returns (address[] memory);

    function getAccountLiquidity(address account)
        external
        view
        returns (
            uint256,
            uint256,
            uint256
        );
}

interface IWBNB is IERC20 {
    function deposit() external payable;

    function withdraw(uint256 wad) external;
}

interface IVBNB {
    function mint() external payable;

    function redeem(uint256 redeemTokens) external returns (uint256);

    function redeemUnderlying(uint256 redeemAmount) external returns (uint256);

    function borrow(uint256 borrowAmount) external returns (uint256);

    function repayBorrow() external payable;

    // function getAccountSnapshot(address account)
    //     external
    //     view
    //     returns (
    //         uint256,
    //         uint256,
    //         uint256,
    //         uint256
    //     );

    function balanceOfUnderlying(address owner) external returns (uint256);

    function borrowBalanceCurrent(address account) external returns (uint256);
}

interface IVToken is IERC20 {
    function underlying() external returns (address);

    function mint(uint256 mintAmount) external returns (uint256);

    function redeem(uint256 redeemTokens) external returns (uint256);

    function redeemUnderlying(uint256 redeemAmount) external returns (uint256);

    function borrow(uint256 borrowAmount) external returns (uint256);

    function repayBorrow(uint256 repayAmount) external returns (uint256);

    function balanceOfUnderlying(address owner) external returns (uint256);

    function borrowBalanceCurrent(address account) external returns (uint256);
}

contract StratVLEV2 is Ownable, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;
    using Address for address;
    using SafeMath for uint256;

    bool public isAutoComp;
    bool public wantIsWBNB = false;
    address public token0Address;
    address public token1Address;
    address public lockerAddress;
    address public wantAddress;
    address public vTokenAddress;
    address[] public venusMarkets;
    address public uniRouterAddress;

    address public constant wbnbAddress =
        0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
    address public constant venusAddress =
        0xcF6BB5389c92Bdda8a3747Ddb454cB7a64626C63;
    address public constant earnedAddress = venusAddress;
    address public constant venusDistributionAddress =
        0xfD36E2c2a6789Db23113685031d7F16329158384;

    address public pufferFarmAddress;
    address public PUFFAddress;
    address public govAddress; // timelock contract

    uint256 public wantLockedTotal = 0;
    uint256 public lastEarnBlock = 0;

    uint256 public buyBackRate = 4000;   // default 40%
    uint256 public constant buyBackRateMax = 10000; // 100 = 1%
    uint256 public constant buyBackRateUL = 800; // 8% upperlimit
    address public buyBackAddress = 0x000000000000000000000000000000000000dEaD;

    uint256 public deleverAmtFactorMax = 50; // 0.5% is the max amt to delever for deleverageOnce()
    uint256 public constant deleverAmtFactorMaxUL = 500;

    uint256 public deleverAmtFactorSafe = 20; // 0.2% is the safe amt to delever for deleverageOnce()
    uint256 public constant deleverAmtFactorSafeUL = 500;

    uint256 public slippageFactor = 950; // 5% default slippage tolerance
    uint256 public constant slippageFactorUL = 995;

    address[] public venusToToken0Path;
    address[] public venusToToken1Path;
    address[] public venusToWantPath;
    address[] public earnedToPUFFPath;

    /**
     * @dev Variables that can be changed to config profitability and risk:
     * {borrowRate}          - What % of our collateral do we borrow per leverage level.
     * {borrowDepth}         - How many levels of leverage do we take.
     * {BORROW_RATE_MAX}     - A limit on how much we can push borrow risk.
     * {BORROW_DEPTH_MAX}    - A limit on how many steps we can leverage.
     */
    uint256 public borrowRate = 585;
    uint256 public borrowDepth = 3;
    uint256 public constant BORROW_RATE_MAX = 595;
    uint256 public constant BORROW_RATE_MAX_HARD = 599;
    uint256 public constant BORROW_DEPTH_MAX = 6;
    bool onlyGov = true;

    uint256 public supplyBal = 0; // Cached want supplied to venus
    uint256 public borrowBal = 0; // Cached want borrowed from venus
    uint256 public supplyBalTargeted = 0; // Cached targetted want supplied to venus to achieve desired leverage
    uint256 public supplyBalMin = 0;

    /**
     * @dev Events that the contract emits
     */

    constructor(
        address _wantAddress,
        address _vTokenAddress,
        bool _isAutoComp
    ) public {
        govAddress = 0xe14e100961AC57a401B215b11de751e272e9d865;
        pufferFarmAddress = 0x031a7843e2cA990397591d34302F35fA8f856Cc6;
        PUFFAddress = 0xe68A1B5CbD28CA7107296f0c7ba6fF169885F100;

        wantAddress = _wantAddress;
        if (wantAddress == wbnbAddress) {
            wantIsWBNB = true;
        }
        token0Address = PUFFAddress;
        token1Address = wbnbAddress;
        lockerAddress = 0xf91dCDCAcED82b08bB5309454AEADE448FC05DeC;
        
        venusToToken0Path = [venusAddress,wbnbAddress,PUFFAddress];
        venusToToken1Path = [venusAddress,wbnbAddress];
        venusToWantPath = [venusAddress,wbnbAddress];
        if (wantAddress != wbnbAddress) {
            venusToWantPath.push(wantAddress);
        }
        earnedToPUFFPath = [venusAddress,wbnbAddress,PUFFAddress];

        buyBackRate = 4000;
        isAutoComp = _isAutoComp;

        vTokenAddress = _vTokenAddress;
        venusMarkets = [vTokenAddress];
        uniRouterAddress = 0x10ED43C718714eb63d5aA57B78B54704E256024E;

        transferOwnership(pufferFarmAddress);

        _resetAllowances();

        IVenusDistribution(venusDistributionAddress).enterMarkets(venusMarkets);
    }

    event SetSettings(
        uint256 _buyBackRate,
        uint256 _slippageFactor,
        uint256 _deleverAmtFactorMax,
        uint256 _deleverAmtFactorSafe
    );

    event SetGov(address _govAddress);
    event SetOnlyGov(bool _onlyGov);
    event SetAutoComp(bool _isAutoComp);
    event SetUniRouterAddress(address _uniRouterAddress);
    event SetBuyBackAddress(address _buyBackAddress);
    event SetRewardsAddress(address _rewardsAddress);
    event SetVTokenAddress(address _vTokenAddress);

    modifier onlyAllowGov() {
        require(msg.sender == govAddress, "!gov");
        _;
    }

    function _supply(uint256 _amount) internal {
        if (wantIsWBNB) {
            IVBNB(vTokenAddress).mint{value: _amount}();
        } else {
            IVToken(vTokenAddress).mint(_amount);
        }
    }

    function _removeSupply(uint256 _amount) internal {
        IVToken(vTokenAddress).redeemUnderlying(_amount);
    }

    function _borrow(uint256 _amount) internal {
        IVToken(vTokenAddress).borrow(_amount);
    }

    function _repayBorrow(uint256 _amount) internal {
        if (wantIsWBNB) {
            IVBNB(vTokenAddress).repayBorrow{value: _amount}();
        } else {
            IVToken(vTokenAddress).repayBorrow(_amount);
        }
    }

    function deposit(uint256 _wantAmt)
        public
        onlyOwner
        nonReentrant
        returns (uint256)
    {
        updateBalance();

        IERC20(wantAddress).safeTransferFrom(
            address(msg.sender),
            address(this),
            _wantAmt
        );
        
        wantLockedTotal = wantLockedTotal.add(_wantAmt);

        if (isAutoComp) {
            _farm(true);
        }

        return _wantAmt;
    }

    function farm(bool _withLev) public nonReentrant onlyAllowGov {
        _farm(_withLev);
    }

    function _farm(bool _withLev) internal {
        if (wantIsWBNB) {
            _unwrapBNB(); // WBNB -> BNB. Venus accepts BNB, not WBNB.
        }

        _leverage(_withLev);

        updateBalance();

        deleverageUntilNotOverLevered(); // It is possible to still be over-levered after depositing.
    }
    
    function unfarm(uint256 _wantAmt) public nonReentrant onlyAllowGov {
        _unfarm(_wantAmt);
    }

    function _unfarm(uint256 _wantAmt) internal {
        _deleverage(_wantAmt);
        
        if (wantIsWBNB) {
            _wrapBNB(); // wrap BNB -> WBNB before sending it back to user
        }
    }

    /**
     * @dev Repeatedly supplies and borrows bnb following the configured {borrowRate} and {borrowDepth}
     * into the vToken contract.
     */
    function _leverage(bool _withLev) internal {
        if (_withLev) {
            for (uint256 i = 0; i < borrowDepth; i++) {
                uint256 amount = venusWantBal();
                _supply(amount);
                amount = amount.mul(borrowRate).div(1000);
                _borrow(amount);
            }
        }

        _supply(venusWantBal()); // Supply remaining want that was last borrowed.
    }

    function leverageOnce() public onlyAllowGov {
        _leverageOnce();
    }

    function _leverageOnce() internal {
        updateBalance(); // Updates borrowBal & supplyBal & supplyBalTargeted & supplyBalMin
        uint256 borrowAmt = supplyBal.mul(borrowRate).div(1000).sub(borrowBal);
        if (borrowAmt > 0) {
            _borrow(borrowAmt);
            _supply(venusWantBal());
        }
        updateBalance(); // Updates borrowBal & supplyBal & supplyBalTargeted & supplyBalMin
    }

    /**
     * @dev Redeem to the desired leverage amount, then use it to repay borrow.
     * If already over leverage, redeem max amt redeemable, then use it to repay borrow.
     */
    function deleverageOnce() public onlyAllowGov {
        _deleverageOnce();
    }

    function _deleverageOnce() internal {
        updateBalance(); // Updates borrowBal & supplyBal & supplyBalTargeted & supplyBalMin

        if (supplyBal <= 0) {
            return;
        }

        uint256 deleverAmt;
        uint256 deleverAmtMax = supplyBal.mul(deleverAmtFactorMax).div(10000); // 0.5%

        if (supplyBal <= supplyBalMin) {
            // If very over levered, delever 0.2% at a time
            deleverAmt = supplyBal.mul(deleverAmtFactorSafe).div(10000);
        } else if (supplyBal <= supplyBalTargeted) {
            deleverAmt = supplyBal.sub(supplyBalMin);
        } else {
            deleverAmt = supplyBal.sub(supplyBalTargeted);
        }

        if (deleverAmt > deleverAmtMax) {
            deleverAmt = deleverAmtMax;
        }

        _removeSupply(deleverAmt);

        if (wantIsWBNB) {
            _unwrapBNB(); // WBNB -> BNB
            _repayBorrow(address(this).balance);
        } else {
            _repayBorrow(wantLockedInHere());
        }

        updateBalance(); // Updates borrowBal & supplyBal & supplyBalTargeted & supplyBalMin
    }

    /**
     * @dev Redeem the max possible, use it to repay borrow
     */
    function deleverageUntilNotOverLevered() public {
        // updateBalance(); // To be more accurate, call updateBalance() first to cater for changes due to interest rates

        // If borrowRate slips below targetted borrowRate, withdraw the max amt first.
        // Further actual deleveraging will take place later on.
        // (This can happen in when net interest rate < 0, and supplied balance falls below targeted.)
        while (supplyBal > 0 && supplyBal <= supplyBalTargeted) {
            _deleverageOnce();
        }
    }

    /**
     * @dev Incrementally alternates between paying part of the debt and withdrawing part of the supplied
     * collateral. Continues to do this untill all want tokens is withdrawn. For partial deleveraging,
     * this continues until at least _minAmt of want tokens is reached.
     */

    function _deleverage(uint256 _minAmt) internal {
        updateBalance(); // Updates borrowBal & supplyBal & supplyBalTargeted & supplyBalMin

        deleverageUntilNotOverLevered();

        if (wantIsWBNB) {
            _wrapBNB(); // WBNB -> BNB
        }

        uint256 supplyRemovableMax = supplyBal.sub(supplyBalMin);
        if (_minAmt < supplyRemovableMax) {
            // If _minAmt to deleverage is less than supplyRemovableMax, just remove _minAmt
            supplyRemovableMax = _minAmt;
        }
        _removeSupply(supplyRemovableMax);

        uint256 wantBal = wantLockedInHere();

        // Recursively repay borrowed + remove more from supplied
        while (wantBal < borrowBal) {
            // If only partially deleveraging, when sufficiently deleveraged, do not repay anymore
            if (wantBal >= _minAmt) {
                return;
            }

            _repayBorrow(wantBal);

            updateBalance(); // Updates borrowBal & supplyBal & supplyBalTargeted & supplyBalMin

            supplyRemovableMax = supplyBal.sub(supplyBalMin);
            if (_minAmt < supplyRemovableMax) {
                // If _minAmt to deleverage is less than supplyRemovableMax, just remove _minAmt
                supplyRemovableMax = _minAmt;
            }
            _removeSupply(supplyRemovableMax);

            wantBal = wantLockedInHere();
        }

        // When sufficiently deleveraged, do not repay
        if (wantBal >= _minAmt) {
            return;
        }

        // Make a final repayment of borrowed
        _repayBorrow(borrowBal);

        // remove all supplied
        uint256 vTokenBal = IERC20(vTokenAddress).balanceOf(address(this));
        IVToken(vTokenAddress).redeem(vTokenBal);
    }

    /**
     * @dev Updates the risk profile and rebalances the vault funds accordingly.
     * @param _borrowRate percent to borrow on each leverage level.
     * @param _borrowDepth how many levels to leverage the funds.
     */
    function rebalance(uint256 _borrowRate, uint256 _borrowDepth)
        external
        onlyAllowGov
    {
        require(_borrowRate <= BORROW_RATE_MAX, "!rate");
        require(_borrowDepth <= BORROW_DEPTH_MAX, "!depth");

        borrowRate = _borrowRate;
        borrowDepth = _borrowDepth;

        updateBalance(); // Updates borrowBal & supplyBal & supplyBalTargeted & supplyBalMin
        deleverageUntilNotOverLevered();
    }

    function earn() external nonReentrant whenNotPaused {
        if (onlyGov) {
            require(msg.sender == govAddress, "!gov");
        }

        IVenusDistribution(venusDistributionAddress).claimVenus(address(this));

        uint256 earnedAmt = IERC20(venusAddress).balanceOf(address(this));

        earnedAmt = buyBack(earnedAmt);
        

        if (venusAddress != token0Address) {
            // Swap half earned to token0
            _safeSwap(
                uniRouterAddress,
                earnedAmt.div(2),
                slippageFactor,
                venusToToken0Path,
                address(this),
                block.timestamp.add(600)
            );
        }

        if (venusAddress != token1Address) {
            // Swap half earned to token1
            _safeSwap(
                uniRouterAddress,
                earnedAmt.div(2),
                slippageFactor,
                venusToToken1Path,
                address(this),
                block.timestamp.add(600)
            );
        }

        // Get want tokens, ie. add liquidity
        uint256 token0Amt = IERC20(token0Address).balanceOf(address(this));
        uint256 token1Amt = IERC20(token1Address).balanceOf(address(this));
        if (token0Amt > 0 && token1Amt > 0) {
            IPancakeRouter02(uniRouterAddress).addLiquidity(
                token0Address,
                token1Address,
                token0Amt,
                token1Amt,
                0,
                0,
                lockerAddress,
                block.timestamp.add(600)
            );
        }

        lastEarnBlock = block.number;

        _farm(false); // Supply wantToken without leverage, to cater for net -ve interest rates.
    }

    function buyBack(uint256 _earnedAmt) internal returns (uint256) {
        if (buyBackRate <= 0) {
            return _earnedAmt;
        }

        uint256 buyBackAmt = _earnedAmt.mul(buyBackRate).div(buyBackRateMax);

        _safeSwap(
            uniRouterAddress,
            buyBackAmt,
            slippageFactor,
            earnedToPUFFPath,
            buyBackAddress,
            block.timestamp.add(600)
        );

        return _earnedAmt.sub(buyBackAmt);
    }

    function withdraw(uint256 _wantAmt)
        external
        onlyOwner
        nonReentrant
        whenNotPaused
        returns (uint256)
    {
        uint256 wantBal = IERC20(wantAddress).balanceOf(address(this));
        if (wantBal < _wantAmt && isAutoComp) {
            _deleverage(_wantAmt.sub(wantBal));
            if (wantIsWBNB) {
                _wrapBNB(); // wrap BNB -> WBNB before sending it back to user
            }
            wantBal = IERC20(wantAddress).balanceOf(address(this));
        }

        if (wantBal < _wantAmt) {
            _wantAmt = wantBal;
        }
        
        wantLockedTotal = wantLockedTotal.sub(_wantAmt);

        IERC20(wantAddress).safeTransfer(pufferFarmAddress, _wantAmt);

        if (isAutoComp) {
            _farm(false);
        }

        return _wantAmt;
    }

    /**
     * @dev Pauses the strat.
     */
    function pause() public onlyAllowGov {
        _pause();
    }

    /**
     * @dev Unpauses the strat.
     */
    function unpause() external onlyAllowGov {
        _unpause();
        _resetAllowances();
    }

    function _resetAllowances() internal {
        IERC20(venusAddress).safeApprove(uniRouterAddress, uint256(0));
        IERC20(venusAddress).safeIncreaseAllowance(
            uniRouterAddress,
            uint256(-1)
        );

        IERC20(wantAddress).safeApprove(uniRouterAddress, uint256(0));
        IERC20(wantAddress).safeIncreaseAllowance(
            uniRouterAddress,
            uint256(-1)
        );
        
        IERC20(token0Address).safeApprove(uniRouterAddress, uint256(0));
        IERC20(token0Address).safeIncreaseAllowance(
            uniRouterAddress,
            uint256(-1)
        );
        
        IERC20(token1Address).safeApprove(uniRouterAddress, uint256(0));
        IERC20(token1Address).safeIncreaseAllowance(
            uniRouterAddress,
            uint256(-1)
        );

        if (!wantIsWBNB) {
            IERC20(wantAddress).safeApprove(vTokenAddress, uint256(0));
            IERC20(wantAddress).safeIncreaseAllowance(
                vTokenAddress,
                uint256(-1)
            );
        }
    }

    function resetAllowances() public onlyAllowGov {
        _resetAllowances();
    }

    /**
     * @dev Updates want locked in Venus after interest is accrued to this very block.
     * To be called before sensitive operations.
     */
    function updateBalance() public {
        supplyBal = IVToken(vTokenAddress).balanceOfUnderlying(address(this)); // a payable function because of acrueInterest()
        borrowBal = IVToken(vTokenAddress).borrowBalanceCurrent(address(this));
        supplyBalTargeted = borrowBal.mul(1000).div(borrowRate);
        supplyBalMin = borrowBal.mul(1000).div(BORROW_RATE_MAX_HARD);
    }

    // function wantLockedTotal() public view returns (uint256) {
    //     return wantLockedInHere().add(supplyBal).sub(borrowBal);
    // }

    function wantLockedInHere() public view returns (uint256) {
        uint256 wantBal = IERC20(wantAddress).balanceOf(address(this));
        if (wantIsWBNB) {
            uint256 bnbBal = address(this).balance;
            return bnbBal.add(wantBal);
        } else {
            return wantBal;
        }
    }

    /**
     * @dev Returns balance of want. If wantAddress is WBNB, returns BNB balance, not WBNB balance.
     */
    function venusWantBal() public view returns (uint256) {
        if (wantIsWBNB) {
            return address(this).balance;
        }
        return IERC20(wantAddress).balanceOf(address(this));
    }

    function setSettings(
        uint256 _buyBackRate,
        uint256 _slippageFactor,
        uint256 _deleverAmtFactorMax,
        uint256 _deleverAmtFactorSafe
    ) public onlyAllowGov {
        require(_buyBackRate <= buyBackRateUL, "_buyBackRate too high");
        buyBackRate = _buyBackRate;

        require(
            _slippageFactor <= slippageFactorUL,
            "_slippageFactor too high"
        );
        slippageFactor = _slippageFactor;

        require(
            _deleverAmtFactorMax <= deleverAmtFactorMaxUL,
            "_deleverAmtFactorMax too high"
        );
        deleverAmtFactorMax = _deleverAmtFactorMax;

        require(
            _deleverAmtFactorSafe <= deleverAmtFactorSafeUL,
            "_deleverAmtFactorSafe too high"
        );
        deleverAmtFactorSafe = _deleverAmtFactorSafe;

        emit SetSettings(
            _buyBackRate,
            _slippageFactor,
            _deleverAmtFactorMax,
            _deleverAmtFactorSafe
        );
    }
    
    function setAutoComp(bool _isAutoComp) public onlyAllowGov {
        isAutoComp = _isAutoComp;
        emit SetAutoComp(_isAutoComp);
    }

    function setGov(address _govAddress) public onlyAllowGov {
        govAddress = _govAddress;
        emit SetGov(_govAddress);
    }

    function setOnlyGov(bool _onlyGov) public onlyAllowGov {
        onlyGov = _onlyGov;
        emit SetOnlyGov(_onlyGov);
    }

    function setUniRouterAddress(address _uniRouterAddress)
        public
        onlyAllowGov
    {
        uniRouterAddress = _uniRouterAddress;
        _resetAllowances();
        emit SetUniRouterAddress(_uniRouterAddress);
    }

    function setBuyBackAddress(address _buyBackAddress) public onlyAllowGov {
        buyBackAddress = _buyBackAddress;
        emit SetBuyBackAddress(_buyBackAddress);
    }
    
    function setVTokenAddress(address _vTokenAddress) public onlyAllowGov {
        vTokenAddress = _vTokenAddress;
        emit SetVTokenAddress(_vTokenAddress);
    }

    function inCaseTokensGetStuck(
        address _token,
        uint256 _amount,
        address _to
    ) public onlyAllowGov {
        require(_token != earnedAddress, "!safe");
        require(_token != wantAddress, "!safe");
        require(_token != vTokenAddress, "!safe");

        IERC20(_token).safeTransfer(_to, _amount);
    }

    function _wrapBNB() internal {
        // BNB -> WBNB
        uint256 bnbBal = address(this).balance;
        if (bnbBal > 0) {
            IWBNB(wbnbAddress).deposit{value: bnbBal}(); // BNB -> WBNB
        }
    }

    function _unwrapBNB() internal {
        // WBNB -> BNB
        uint256 wbnbBal = IERC20(wbnbAddress).balanceOf(address(this));
        if (wbnbBal > 0) {
            IWBNB(wbnbAddress).withdraw(wbnbBal);
        }
    }

    /**
     * @dev We should not have significant amts of BNB in this contract if any at all.
     * In case we do (eg. Venus returns all users' BNB to this contract or for any other reason),
     * We can wrap all BNB, allowing users to withdraw() as per normal.
     */
    function wrapBNB() public onlyAllowGov {
        require(wantIsWBNB, "!wantIsWBNB");
        _wrapBNB();
    }

    function _safeSwap(
        address _uniRouterAddress,
        uint256 _amountIn,
        uint256 _slippageFactor,
        address[] memory _path,
        address _to,
        uint256 _deadline
    ) internal {
        uint256[] memory amounts =
            IPancakeRouter02(_uniRouterAddress).getAmountsOut(_amountIn, _path);
        uint256 amountOut = amounts[amounts.length.sub(1)];

        IPancakeRouter02(_uniRouterAddress).swapExactTokensForTokens(
            _amountIn,
            amountOut.mul(_slippageFactor).div(1000),
            _path,
            _to,
            _deadline
        );
    }

    receive() external payable {}
}
