// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "./StratX2.sol";

contract StratX2_PCS is StratX2 {
    constructor(
        address _wantAddress,
        uint256 _pid,
        bool _isCAKEStaking
    ) public {
        wbnbAddress = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
        govAddress = 0xe14e100961AC57a401B215b11de751e272e9d865;
        pufferFarmAddress = 0x031a7843e2cA990397591d34302F35fA8f856Cc6;
        PUFFAddress = 0xe68A1B5CbD28CA7107296f0c7ba6fF169885F100;

        wantAddress = _wantAddress;
        token0Address = PUFFAddress;
        token1Address = wbnbAddress;
        earnedAddress = 0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82;
        lockerAddress = 0xf91dCDCAcED82b08bB5309454AEADE448FC05DeC;

        farmContractAddress = 0x73feaa1eE314F8c655E354234017bE2193C9E24E;
        pid = _pid;
        isCAKEStaking = _isCAKEStaking;
        isAutoComp = true;

        uniRouterAddress = 0x10ED43C718714eb63d5aA57B78B54704E256024E;
        earnedToPUFFPath = [earnedAddress,wbnbAddress,PUFFAddress];
        earnedToToken0Path = [earnedAddress,wbnbAddress,PUFFAddress];
        earnedToToken1Path = [earnedAddress,wbnbAddress];
        token0ToEarnedPath = [PUFFAddress,wbnbAddress,earnedAddress];
        token1ToEarnedPath = [wbnbAddress,earnedAddress];

        buyBackRate = 4000;

        transferOwnership(pufferFarmAddress);
    }
}
