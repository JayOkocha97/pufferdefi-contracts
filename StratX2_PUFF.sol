// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "./StratX2.sol";

contract StratX2_PUFF is StratX2 {
    constructor(
        address _wantAddress
    ) public {
        wbnbAddress = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
        govAddress = 0xe14e100961AC57a401B215b11de751e272e9d865;
        pufferFarmAddress = 0x031a7843e2cA990397591d34302F35fA8f856Cc6;
        PUFFAddress = 0xe68A1B5CbD28CA7107296f0c7ba6fF169885F100;

        wantAddress = _wantAddress;
        token0Address = PUFFAddress;
        token1Address = wbnbAddress;
        earnedAddress = 0x0000000000000000000000000000000000000000;
        lockerAddress = 0xf91dCDCAcED82b08bB5309454AEADE448FC05DeC;

        farmContractAddress = 0x0000000000000000000000000000000000000000;
        pid = 0;
        isCAKEStaking = false;
        isAutoComp = false;

        uniRouterAddress = 0x10ED43C718714eb63d5aA57B78B54704E256024E;

        buyBackRate = 4000;

        transferOwnership(pufferFarmAddress);
    }
    
    function _farm() internal override {}

    function _unfarm(uint256 _wantAmt) internal override {}

    function earn() public override nonReentrant whenNotPaused {}

    function convertDustToEarned() public override nonReentrant whenNotPaused {}
}
