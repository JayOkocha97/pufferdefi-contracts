// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "./helpers/Ownable.sol";
import "./helpers/ReentrancyGuard.sol";
import "./PufferToken.sol";
import "./libraries/SafeBEP20.sol";


// For interacting with our own strategy
interface IStrategy {
    // Total want tokens managed by stratfegy
    function wantLockedTotal() external view returns (uint256);

    // Main want token compounding function
    function earn() external;

    // Transfer want tokens autoFarm -> strategy
    function deposit(uint256 _wantAmt)
        external
        returns (uint256);

    // Transfer want tokens strategy -> autoFarm
    function withdraw(uint256 _wantAmt)
        external
        returns (uint256);

    function inCaseTokensGetStuck(
        address _token,
        uint256 _amount,
        address _to
    ) external;
}

// PufferFarm is the master of Puffer Token (PUFF). He can make PUFF and he is a fair guy.
//
// Note that it's ownable and the owner wields tremendous power. Initially the ownership is
// transferred to TimeLock contract and Later the ownership will be transferred to a governance smart
// contract once $PUFF is sufficiently distributed and the community can show to govern itself.
//
// Have fun reading it. Hopefully it's bug-free. God bless.
contract PufferFarm is Ownable, ReentrancyGuard {
    using SafeMath for uint256;
    using SafeBEP20 for IBEP20;

    // Info of each user.
    struct UserInfo {
        uint256 amount; // How many LP tokens the user has provided.
        uint256 rewardDebt; // Reward debt. See explanation below.
		uint256 rewardLockedUp; // Reward locked up.
        //
        // We do some fancy math here. Basically, any point in time, the amount of PUFFs
        // entitled to a user but is pending to be distributed is:
        //
        //   pending reward = (user.amount * pool.accPuffPerShare) - user.rewardDebt
        //
        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
        //   1. The pool's `accPuffPerShare` (and `lastRewardBlock`) gets updated.
        //   2. User receives the pending reward sent to his/her address.
        //   3. User's `amount` gets updated.
        //   4. User's `rewardDebt` gets updated.
    }

    // Info of each pool.
    struct PoolInfo {
        IBEP20 lpToken; // Address of LP token contract.
        uint256 allocPoint; // How many allocation points assigned to this pool. PUFFs to distribute per block.
        uint256 lastRewardBlock; // Last block number that PUFFs distribution occurs.
        uint256 accPuffPerShare; // Accumulated PUFFs per share, times 1e12. See below.
        uint16 depositFeeBP; // Deposit fee in basis points
        address strat; // Strategy address that will auto compound want tokens
    }

    // The PUFF Token!
    PufferToken public puff;
    // Dev address.
    address public devAddr;
    // PUFF tokens created per block.
    uint256 public puffPerBlock;
    // Deposit Fee address
    address public feeAddress;
    
    // Harvest time (how many block);
    uint256 public harvestTime; 
	// Start Block Harvest
    uint256 public startBlockHarvest;    

    // Info of each pool.
    PoolInfo[] public poolInfo;
    // Info of each user that stakes LP tokens.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    // Total allocation points. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint = 0;
    // The block number when PUFF mining starts.
    uint256 public startBlock;
	// Total locked up rewards
    uint256 public totalLockedUpRewards;	
	
    // Referral Bonus in basis points. Initially set to 3%
    uint256 public refBonusBP = 300;
    // Max deposit fee: 10%.
    uint16 public constant MAXIMUM_DEPOSIT_FEE_BP = 1000;
    // Max referral commission rate: 20%.
    uint16 public constant MAXIMUM_REFERRAL_BP = 2000;
    // Referral Mapping
    mapping(address => address) public referrers; // account_address -> referrer_address
    mapping(address => uint256) public referredCount; // referrer_address -> num_of_referred
    // Pool Exists Mapper
    mapping(IBEP20 => bool) public poolExistence;
    // Pool ID Tracker Mapper
    mapping(IBEP20 => uint256) public poolIdForLpAddress;

    // Initial emission rate: 1 PUFF per block.
    uint256 public constant INITIAL_EMISSION_RATE = 1 ether;
	
    // Initial harvest time: 1 day.
    uint256 public constant INITIAL_HARVEST_TIME = 28800;	
	
    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(
        address indexed user,
        uint256 indexed pid,
        uint256 amount
    );
    event SetFeeAddress(address indexed user, address indexed _devAddress);
    event SetDevAddress(address indexed user, address indexed _feeAddress);
    event Referral(address indexed _referrer, address indexed _user);
    event ReferralPaid(address indexed _user, address indexed _userTo, uint256 _reward);
    event ReferralBonusBpChanged(uint256 _oldBp, uint256 _newBp);
    event EmissionRateUpdated(address indexed caller, uint256 previousAmount, uint256 newAmount);
	event UpdateHarvestTime(address indexed caller, uint256 _oldHarvestTime, uint256 _newHarvestTime);
	event UpdateStartBlockHarvest(address indexed caller, uint256 _oldStartBlockHarvest, uint256 _newStartBlockHarvest);
	event RewardLockedUp(address indexed user, uint256 indexed pid, uint256 amountLockedUp);

    constructor(
        PufferToken _puff,
        address _devAddr,
        address _feeAddress,
        uint256 _startBlock
    ) public {
        puff = _puff;
        devAddr = _devAddr;
        feeAddress = _feeAddress;
        puffPerBlock = INITIAL_EMISSION_RATE;
        harvestTime = INITIAL_HARVEST_TIME;
        startBlock = _startBlock;
        startBlockHarvest = _startBlock;
    }

    // Get number of pools added.
    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    function getPoolIdForLpToken(IBEP20 _lpToken) external view returns (uint256) {
        require(poolExistence[_lpToken] != false, "getPoolIdForLpToken: do not exist");
        return poolIdForLpAddress[_lpToken];
    }

    // Modifier to check Duplicate pools
    modifier nonDuplicated(IBEP20 _lpToken) {
        require(poolExistence[_lpToken] == false, "nonDuplicated: duplicated");
        _;
    }

    // Add a new lp to the pool. Can only be called by the owner.
    function add(
        uint256 _allocPoint,
        IBEP20 _lpToken,
        uint16 _depositFeeBP,
        bool _withUpdate,
        address _strat
    ) public onlyOwner nonDuplicated(_lpToken) {
        require(_depositFeeBP <= MAXIMUM_DEPOSIT_FEE_BP, "add: invalid deposit fee basis points");
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolExistence[_lpToken] = true;
        poolInfo.push(
            PoolInfo({
                lpToken: _lpToken,
                allocPoint: _allocPoint,
                lastRewardBlock: lastRewardBlock,
                accPuffPerShare: 0,
                depositFeeBP: _depositFeeBP,
                strat: _strat
            })
        );
        poolIdForLpAddress[_lpToken] = poolInfo.length - 1;
    }

    // Update the given pool's PUFF allocation point and deposit fee. Can only be called by the owner.
    function set(
        uint256 _pid,
        uint256 _allocPoint,
        uint16 _depositFeeBP,
        bool _withUpdate
    ) public onlyOwner {
        require(_depositFeeBP <= MAXIMUM_DEPOSIT_FEE_BP, "set: invalid deposit fee basis points");
        if (_withUpdate) {
            massUpdatePools();
        }
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(
            _allocPoint
        );
        poolInfo[_pid].allocPoint = _allocPoint;
        poolInfo[_pid].depositFeeBP = _depositFeeBP;
    }

    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to)
        public
        pure
        returns (uint256)
    {
        return _to.sub(_from);
    }

    // View function to see pending PUFFs on frontend.
    function pendingPuff(uint256 _pid, address _user)
        external
        view
        returns (uint256)
    {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accPuffPerShare = pool.accPuffPerShare;
        uint256 lpSupply = IStrategy(pool.strat).wantLockedTotal();
        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
            uint256 puffReward = multiplier.mul(puffPerBlock).mul(pool.allocPoint).div(
                    totalAllocPoint
                );
            accPuffPerShare = accPuffPerShare.add(
                puffReward.mul(1e12).div(lpSupply)
            );
        }
        uint256 pending = user.amount.mul(accPuffPerShare).div(1e12).sub(user.rewardDebt);
        return pending.add(user.rewardLockedUp);		
    }
    
    // View function to see total locked on frontend.
    function lockedTotal(uint256 _pid)
        external
        view
        returns (uint256)
    {
        return IStrategy(poolInfo[_pid].strat).wantLockedTotal();
    }

    // Update reward variables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }
        uint256 lpSupply = IStrategy(pool.strat).wantLockedTotal();
        if (lpSupply == 0 || pool.allocPoint == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 puffReward =
            multiplier.mul(puffPerBlock).mul(pool.allocPoint).div(
                totalAllocPoint
            );
        puff.mint(devAddr, puffReward.div(10));
        puff.mint(address(this), puffReward);
        pool.accPuffPerShare = pool.accPuffPerShare.add(
            puffReward.mul(1e12).div(lpSupply)
        );
        pool.lastRewardBlock = block.number;
    }

    // Deposit LP tokens to PufferDeFi for PUFF allocation.
    function deposit(uint256 _pid, uint256 _amount) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);		
		payOrLockupPendingPuff(_pid);
        if (_amount > 0) {
            pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
            if (address(pool.lpToken) == address(puff)) {
                uint256 transferTax = _amount.mul(puff.transferTaxRate()).div(10000);
                _amount = _amount.sub(transferTax);
            }						
            if (pool.depositFeeBP > 0) {
                uint256 depositFee = _amount.mul(pool.depositFeeBP).div(10000);
                user.amount = user.amount.add(_amount).sub(depositFee);
                pool.lpToken.safeTransfer(feeAddress, depositFee);
                pool.lpToken.safeIncreaseAllowance(pool.strat, _amount.sub(depositFee));
                IStrategy(pool.strat).deposit(_amount.sub(depositFee));
            } else {
                user.amount = user.amount.add(_amount);
                pool.lpToken.safeIncreaseAllowance(pool.strat, _amount);
                IStrategy(pool.strat).deposit(_amount);
            }
        }
		
        user.rewardDebt = user.amount.mul(pool.accPuffPerShare).div(1e12);
        emit Deposit(msg.sender, _pid, _amount);
    }	

    // Deposit LP tokens to PufferDeFi for PUFF allocation with referral.
    function deposit(uint256 _pid, uint256 _amount, address _referrer) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        if (_amount > 0 && _referrer != address(0) && _referrer == address(_referrer) && _referrer != msg.sender) {
            setReferral(msg.sender, _referrer);
        }		
		payOrLockupPendingPuff(_pid);

        if (_amount > 0) {			
            pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
            if (address(pool.lpToken) == address(puff)) {
                uint256 transferTax = _amount.mul(puff.transferTaxRate()).div(10000);
                _amount = _amount.sub(transferTax);
            }						
            if (pool.depositFeeBP > 0) {
                uint256 depositFee = _amount.mul(pool.depositFeeBP).div(10000);
                user.amount = user.amount.add(_amount).sub(depositFee);
                pool.lpToken.safeTransfer(feeAddress, depositFee);
                pool.lpToken.safeIncreaseAllowance(pool.strat, _amount.sub(depositFee));
                IStrategy(pool.strat).deposit(_amount.sub(depositFee));
            } else {
                user.amount = user.amount.add(_amount);
                pool.lpToken.safeIncreaseAllowance(pool.strat, _amount);
                IStrategy(pool.strat).deposit(_amount);
            }
        }
		
        user.rewardDebt = user.amount.mul(pool.accPuffPerShare).div(1e12);
        emit Deposit(msg.sender, _pid, _amount);
    }

    // Withdraw LP tokens from PufferDeFi.
    function withdraw(uint256 _pid, uint256 _amount) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount >= _amount, "withdraw: not good");
        updatePool(_pid);
		payOrLockupPendingPuff(_pid);
		
        if (_amount > 0) {
            _amount = IStrategy(pool.strat).withdraw(_amount);
            user.amount = user.amount.sub(_amount);
            pool.lpToken.safeTransfer(address(msg.sender), _amount);
        }
        user.rewardDebt = user.amount.mul(pool.accPuffPerShare).div(1e12);
        emit Withdraw(msg.sender, _pid, _amount);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 _amount = IStrategy(pool.strat).withdraw(user.amount);
        pool.lpToken.safeTransfer(address(msg.sender), _amount);
        emit EmergencyWithdraw(msg.sender, _pid, _amount);
        user.amount = user.amount.sub(_amount);
        user.rewardDebt = 0;
		user.rewardLockedUp = 0;
    }

	// Pay or lockup pending PUFFs.
    function payOrLockupPendingPuff(uint256 _pid) internal {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        uint256 pending = user.amount.mul(pool.accPuffPerShare).div(1e12).sub(user.rewardDebt);
		uint256 totalRewards = pending.add(user.rewardLockedUp);
        uint256 lastBlockHarvest = startBlockHarvest.add(harvestTime);
        if (block.number >= startBlockHarvest && block.number <= lastBlockHarvest) {
            if (pending > 0 || user.rewardLockedUp > 0) {        
                // reset lockup
                totalLockedUpRewards = totalLockedUpRewards.sub(user.rewardLockedUp);
                user.rewardLockedUp = 0;
				
                // send rewards
                safePuffTransfer(msg.sender, totalRewards);
                payReferralCommission(msg.sender, totalRewards);
            }
        } else if (pending > 0) {
            user.rewardLockedUp = user.rewardLockedUp.add(pending);
            totalLockedUpRewards = totalLockedUpRewards.add(pending);
            emit RewardLockedUp(msg.sender, _pid, pending);
        }
    }
	
    // Safe puff transfer function, just in case if rounding error causes pool to not have enough PUFFs.
    function safePuffTransfer(address _to, uint256 _amount) internal {
        uint256 puffBal = puff.balanceOf(address(this));
        bool transferSuccess = false;
        if (_amount > puffBal) {
            transferSuccess = puff.transfer(_to, puffBal);
        } else {
            transferSuccess = puff.transfer(_to, _amount);
        }
        require(transferSuccess, "safePuffTransfer: transfer failed.");
    }

    // Update dev address by the previous dev.
    function setDevAddress(address _devaddr) public {
        require(_devaddr != address(0), "dev: invalid address");
        require(msg.sender == devAddr, "dev: wut?");
        devAddr = _devaddr;
        emit SetDevAddress(msg.sender, _devaddr);
    }

    // Update fee address by the previous fee address.
    function setFeeAddress(address _feeAddress) public {
        require(_feeAddress != address(0), "setFeeAddress: invalid address");
        require(msg.sender == feeAddress, "setFeeAddress: FORBIDDEN");
        feeAddress = _feeAddress;
        emit SetFeeAddress(msg.sender, _feeAddress);
    }


    // updateEmissionRate
    function updateEmissionRate(uint256 _puffPerBlock) public onlyOwner {
        massUpdatePools();
        emit EmissionRateUpdated(msg.sender, puffPerBlock, _puffPerBlock);
        puffPerBlock = _puffPerBlock;
    }
	
    // updateHarvestTime, how many blocks
    function updateHarvestTime(uint256 _harvestTime) public onlyOwner {
        harvestTime = _harvestTime;
		emit UpdateHarvestTime(msg.sender, harvestTime, _harvestTime);
    }	

    // updateStartBlockHarvest
    function updateStartBlockHarvest(uint256 _startBlockHarvest) public onlyOwner {
        startBlockHarvest = _startBlockHarvest;
		emit UpdateStartBlockHarvest(msg.sender, startBlockHarvest, _startBlockHarvest);
    }
	
    // Set Referral Address for a user
    function setReferral(address _user, address _referrer) internal {
        if (_referrer == address(_referrer) && referrers[_user] == address(0) && _referrer != address(0) && _referrer != _user) {
            referrers[_user] = _referrer;
            referredCount[_referrer] += 1;
            emit Referral(_user, _referrer);
        }
    }

    // Get Referral Address for a Account
    function getReferral(address _user) public view returns (address) {
        return referrers[_user];
    }

    // Pay referral commission to the referrer who referred this user.
    function payReferralCommission(address _user, uint256 _pending) internal {
        address referrer = getReferral(_user);
        if (referrer != address(0) && referrer != _user && refBonusBP > 0) {
            uint256 refBonusEarned = _pending.mul(refBonusBP).div(10000);
            puff.mint(referrer, refBonusEarned);
            emit ReferralPaid(_user, referrer, refBonusEarned);
        }
    }

    // Referral Bonus in basis points.
    // Initially set to 3%, this this the ability to increase or decrease the Bonus percentage based on
    // community voting and feedback.
    function updateReferralBonusBp(uint256 _newRefBonusBp) public onlyOwner {
        require(_newRefBonusBp <= MAXIMUM_REFERRAL_BP, "updateRefBonusPercent: invalid referral bonus basis points");
        require(_newRefBonusBp != refBonusBP, "updateRefBonusPercent: same bonus bp set");
        uint256 previousRefBonusBP = refBonusBP;
        refBonusBP = _newRefBonusBp;
        emit ReferralBonusBpChanged(previousRefBonusBP, _newRefBonusBp);
    }
}