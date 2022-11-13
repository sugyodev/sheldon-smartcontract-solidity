pragma solidity ^0.8.0;

import '@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol';
import './IUNSRegistry.sol';

interface IERC20 {
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);
}

interface IExchange {
    function offerNonce(uint256, address) external view returns (uint256);
    function listingNonce(uint256) external view returns (uint256);
    function nonce(address) external view returns (uint256);
}

contract Leasing is OwnableUpgradeable {
    /* Prevent a contract function from being reentrant-called. */
    uint256 reentrancyLockStatus;
    modifier nonReentrant() {
    // On the first call to nonReentrant, _notEntered will be true
        require(reentrancyLockStatus != 2, "ReentrancyGuard: reentrant call");

    // Any calls to nonReentrant after this point will fail
        reentrancyLockStatus = 2;

        _;

    // By storing the original value once again, a refund is triggered (see
    // https://eips.ethereum.org/EIPS/eip-2200)
        reentrancyLockStatus = 1;
    }

    IUNSRegistry public tokenAddress;
    mapping(address => bool) public allowedCurrencies;
    struct Lease {
        address lessor;
        address _lessee;
        bytes32 offerHash;
        uint256 endTime;
        uint256 extendPeriodStartTime;
    }

    mapping(uint256 => Lease) public leases;

    bytes32 public constant LEASE_ORDER_TYPEHASH = keccak256(
        "LeaseOrder(address maker,bool isErc20Offer,uint256 tokenId,address currencyContract,uint256 paymentPerSecond,uint256 initialPeriodSeconds,uint256 initialPeriodPrice,uint256 yearlyPriceIncreaseBasisPoints,uint256 nonce,uint256 listingNonce,uint256 offerNonce,uint256 listingTime,uint256 expirationTime,uint256 salt)"
    );

    bytes32 constant EIP712DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    IExchange public exchangeAddress;

    bytes32 DOMAIN_SEPARATOR;

    uint256 public constant SECONDS_IN_MONTH = 60*60*24*30;
    uint256 public constant SECONDS_IN_YEAR = 365 days;
    
    uint256 public constant royaltyPercentageDenominator = 10000;
    uint256 public royaltyBasisPoints;
    address public royaltyAddress; 

    mapping(bytes32 => bool) cancelledOrders;

    event LeaseOrdersMatched         (bytes32 firstHash, bytes32 secondHash, address indexed firstMaker, address indexed secondMaker);
    event LeaseUpdated(uint256 indexed tokenId, address indexed lessor, address indexed lessee, uint256 endTime, bytes32 offerHash, uint256 extendPeriodStartTime);

    function initialize(address _tokenAddress, address _exchangeAddress, uint256 _chainId, address _royaltyAddress, uint256 _royaltyBasisPoints) public initializer {
        __Ownable_init();
        royaltyAddress = _royaltyAddress;
        royaltyBasisPoints = _royaltyBasisPoints;
        tokenAddress = IUNSRegistry(_tokenAddress);
        exchangeAddress = IExchange(_exchangeAddress);
        DOMAIN_SEPARATOR = hash(EIP712Domain({
            name              : "Eternal Digital Assets Leasing",
            version           : "1.0",
            chainId           : _chainId,
            verifyingContract : address(this)
        }));
        reentrancyLockStatus = 1;
    }

    /* An order, convenience struct. */
    struct LeaseOrder {
        /* Maker address. */
        address maker;
        /* Whether this order is from the lessor or the lessee */
        bool isErc20Offer;
        /* tokenId for the domain */
        uint256 tokenId;
        /* Currency contract (erc20 address or 0x0, which is for native currency payments) */
        address currencyContract;
        /* Payment paymentPerSecond (erc20 tokens or native) PER SECOND */
        uint256 paymentPerSecond;
        /* The period the lessee is leasing for. Used only is lessee orders. */
        uint256 initialPeriodSeconds;
        uint256 initialPeriodPrice;
        uint256 yearlyPriceIncreaseBasisPoints;
        /* Order nonce. To cancel all orders from a user */
        uint256 nonce;
        /* Listing nonce. To cancel listings for tokenId */
        uint256 listingNonce;
        /* Offer nonce. To cancel offers for tokenId and user */
        uint256 offerNonce;
        /* Order creation timestamp. */
        uint256 listingTime;
        /* Order expiration timestamp - 0 for no expiry. */
        uint256 expirationTime;
        /* Order salt to prevent duplicate hashes. */
        uint256 salt;
    }

    function setTokenAddress(address _tokenAddress) external onlyOwner {
        tokenAddress = IUNSRegistry(_tokenAddress);
    }

    function getLessee(uint256 tokenId) internal view returns (address) {
        if (leases[tokenId].endTime < block.timestamp) {
            return address(0);
        }
        return leases[tokenId]._lessee;
    }

    function updateLease(uint256 tokenId, address lessor, address lessee, uint256 endTime, bytes32 offerHash, uint256 extendPeriodStartTime) internal {
        leases[tokenId] = Lease(lessor, lessee, offerHash, endTime, extendPeriodStartTime);
        emit LeaseUpdated(tokenId, lessor, lessee, endTime, offerHash, extendPeriodStartTime);
    }

    modifier onlyLessee(uint256 tokenId) {
        require(msg.sender == getLessee(tokenId), 'Sender is not the lessee');
        _;
    }

    struct EIP712Domain {
        string  name;
        string  version;
        uint256 chainId;
        address verifyingContract;
    }

    function hash(EIP712Domain memory eip712Domain)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(
            EIP712DOMAIN_TYPEHASH,
            keccak256(bytes(eip712Domain.name)),
            keccak256(bytes(eip712Domain.version)),
            eip712Domain.chainId,
            eip712Domain.verifyingContract
        ));
    }

    function setRoyaltyBasisPoints(uint256 _royaltyBasisPoints) external onlyOwner {
        require(_royaltyBasisPoints <= royaltyPercentageDenominator, "Royalty basis points are greater than royalty denominator");
        royaltyBasisPoints = _royaltyBasisPoints;
    }

    function setRoyaltyAddress(address _royaltyAddress) external onlyOwner {
        royaltyAddress = _royaltyAddress;
    }

    function setAllowedCurrency(address _currencyAddress, bool _allowed) external onlyOwner {
        allowedCurrencies[_currencyAddress] = _allowed;
    }

    function reclaimToken(uint256 tokenId) public {
        require(msg.sender == leases[tokenId].lessor, 'Sender is not the lessor');
        require(getLessee(tokenId) == address(0), 'Domain is currently being leased');
        tokenAddress.transferFrom(address(this), msg.sender, tokenId);
    }

    function hashOrder(LeaseOrder memory order)
        public
        pure
        returns (bytes32 hash)
    {
        /* Per EIP 712. */
        return keccak256(bytes.concat(
            abi.encode(
                LEASE_ORDER_TYPEHASH,
                order.maker,
                order.isErc20Offer,
                order.tokenId,
                order.currencyContract,
                order.paymentPerSecond,
                order.initialPeriodSeconds,
                order.initialPeriodPrice
            ),
            abi.encodePacked(
                order.yearlyPriceIncreaseBasisPoints,
                order.nonce,
                order.listingNonce,
                order.offerNonce,
                order.listingTime,
                order.expirationTime,
                order.salt
            )
        ));
    }

    function hashToSign(bytes32 orderHash)
        public
        view
        returns (bytes32 hash)
    {
        /* Calculate the string a user must sign. */
        return keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            orderHash
        ));
    }

    function validateOrderParameters(LeaseOrder memory order, bytes32 hash)
        public
        view
        returns (bool)
    {
        /* Order must be listed and not be expired. */
        if (order.listingTime > block.timestamp || (order.expirationTime != 0 && order.expirationTime <= block.timestamp)) {
            return false;
        }

        if(order.nonce < exchangeAddress.nonce(order.maker)){
            return false;
        }

        if (!tokenAddress.exists(order.tokenId)){
            return false;
        }

        /* Order must not have already been cancelled. */
        if (cancelledOrders[hash]) {
            return false;
        }

        return true;
    }

    function validateOrderAuthorization(bytes32 hash, address maker, bytes memory signature)
        public
        view
        returns (bool)
    {

        /* Calculate hash which must be signed. */
        bytes32 calculatedHashToSign = hashToSign(hash);
        /* (d): Account-only authentication: ECDSA-signed by maker. */
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(signature, (uint8, bytes32, bytes32));
        /* (d.2): New way: order hash signed by maker using sign_typed_data */
        if (ecrecover(calculatedHashToSign, v, r, s) == maker) {
            return true;
        }
        return false;
    }

    /* first order always lessor, second order always lessee */
    function atomicMatch(LeaseOrder memory firstOrder, LeaseOrder memory secondOrder, bytes memory firstSignature, bytes memory secondSignature)
        public
        payable
        nonReentrant
    {
        /* CHECKS */
        require(firstOrder.maker != secondOrder.maker, "Can't order from yourself");
        /* Calculate first order hash. */
        bytes32 firstHash = hashOrder(firstOrder);
        /* Check first order validity. */
        require(validateOrderParameters(firstOrder, firstHash), "First order has invalid parameters");
        require(!firstOrder.isErc20Offer,      "First order is not lessor order");
        require(firstOrder.listingNonce == exchangeAddress.listingNonce(firstOrder.tokenId), "Listing has been cancelled");
        
        /* Calculate second order hash. */
        bytes32 secondHash = hashOrder(secondOrder);
        /* Check second order validity. */
        require(validateOrderParameters(secondOrder, secondHash), "Second order has invalid parameters");
        require(secondOrder.isErc20Offer,    "Second order is not lessee order");
        require(secondOrder.offerNonce == exchangeAddress.offerNonce(secondOrder.tokenId, secondOrder.maker), "Offers have been cancelled");

        /* Prevent self-matching (possibly unnecessary, but safer). */
        require(firstHash != secondHash, "Self-matching orders is prohibited");

        /* Check first order authorization. */
        //require(validateOrderAuthorization(firstHash, firstOrder.maker, firstSignature), "First order failed authorization");

        /* Check second order authorization. */
        //require(validateOrderAuthorization(secondHash, secondOrder.maker, secondSignature), "Second order failed authorization");

        require(allowedCurrencies[secondOrder.currencyContract], "Currency not allowed");
        require(firstOrder.tokenId == secondOrder.tokenId, "Orders domain tokenId missmatch");
        require(firstOrder.currencyContract == secondOrder.currencyContract, "Orders currency contract missmatch");
        require(firstOrder.paymentPerSecond == secondOrder.paymentPerSecond, "Orders payment amount missmatch");        
        require(firstOrder.initialPeriodSeconds == secondOrder.initialPeriodSeconds, "Orders initial period missmatch");
        require(firstOrder.initialPeriodPrice == secondOrder.initialPeriodPrice, "Orders initial period price missmatch");
        require(firstOrder.yearlyPriceIncreaseBasisPoints == secondOrder.yearlyPriceIncreaseBasisPoints, "Orders yearly price increase missmatch");

        /* INTERACTIONS */

        uint256 fullPaymentAmount = secondOrder.initialPeriodPrice;
        uint256 royaltyAmount = (fullPaymentAmount * royaltyBasisPoints) / royaltyPercentageDenominator;
        uint256 requiredPaymentAmount = fullPaymentAmount - royaltyAmount;

        if (firstOrder.currencyContract == address(0)) {
            /* Reentrancy prevented by reentrancyGuard modifier */
            require(requiredPaymentAmount == msg.value, "Supplied less than required");

            if (royaltyAmount > 0) {
                require(royaltyAddress != address(0));
                (bool success,) = royaltyAddress.call{value: royaltyAmount}("");
                require(success, "native token transfer failed. royalties");
            }

            if (requiredPaymentAmount > 0) {
                (bool success,) = firstOrder.maker.call{value: requiredPaymentAmount}("");
                require(success, "native token transfer failed.");
            }
        } else {
            /* Execute first call, assert success. */

            IERC20 paymentContractAddress = IERC20(secondOrder.currencyContract);
            if (royaltyAmount > 0) { 
                require(royaltyAddress != address(0));
                require(paymentContractAddress.transferFrom(secondOrder.maker, royaltyAddress, royaltyAmount), "Payment for asset failed. royalties");
            }
            
            if (requiredPaymentAmount > 0) {
                require(paymentContractAddress.transferFrom(secondOrder.maker, firstOrder.maker, requiredPaymentAmount), "Payment for asset failed");
            }
        }

        /* Execute second call, assert success. */
        address tokenOwner = tokenAddress.ownerOf(firstOrder.tokenId);

        uint256 tokenId = firstOrder.tokenId;

        if (tokenOwner != firstOrder.maker) {
            require(tokenOwner == address(this), "Token not owned by lessor");
            require(firstOrder.maker == leases[tokenId].lessor, "First order maker is not the lessor");
            require(getLessee(tokenId) == secondOrder.maker || getLessee(tokenId) == address(0), "Token already leased by someone else");
        } else {
            tokenAddress.transferFrom(firstOrder.maker, address(this), firstOrder.tokenId);
        }

        updateLease(
            tokenId,
            firstOrder.maker,
            secondOrder.maker,
            /* note: if the user accepts another listing while still leasing they will reset their lease.
             *  this is intentional, as it allows the user to accept a new listing without having to cancel
             *  their current lease, while ensuring that they cannot stack initial periods
             */
            block.timestamp + secondOrder.initialPeriodSeconds,
            secondHash,
            block.timestamp + secondOrder.initialPeriodSeconds
        );

        /* LOGS */

        /* Log match event. */
        emit LeaseOrdersMatched(firstHash, secondHash, firstOrder.maker, secondOrder.maker);
    }

    function extendLease(LeaseOrder memory secondOrder, uint256 extendToTime)
        public
        payable
        nonReentrant
        onlyLessee(secondOrder.tokenId)
    {
        bytes32 secondHash = hashOrder(secondOrder);

        Lease memory lease = leases[secondOrder.tokenId];

        require(lease.offerHash == secondHash, "Offer hash missmatch");

        if (extendToTime == lease.endTime) {
            return;
        }

        require(extendToTime > lease.endTime, "Extend to time must be greater than current lease end");

        uint256 paymentPerSecond = secondOrder.paymentPerSecond;
        uint256 yearlyPriceIncreaseBasisPoints = secondOrder.yearlyPriceIncreaseBasisPoints;
        uint256 extendPeriodStartTime = lease.extendPeriodStartTime;
        uint256 currentEndTime = lease.endTime;
        uint256 fullPaymentAmount = 0;

        for (uint256 i = extendPeriodStartTime; i < extendToTime; i += 365 days) {
            if( i >= currentEndTime) {
                if(i + 365 days > extendToTime) {
                    fullPaymentAmount += (extendToTime - i) * paymentPerSecond;
                } else{
                    fullPaymentAmount += 365 days * paymentPerSecond;
                }
            } else if (i + 365 days > currentEndTime) {
                fullPaymentAmount += ((i + 365 days) - currentEndTime) * paymentPerSecond;
            }
            
            paymentPerSecond += (paymentPerSecond * yearlyPriceIncreaseBasisPoints) / 10000;
        }

        uint256 royaltyAmount = (fullPaymentAmount * royaltyBasisPoints) / royaltyPercentageDenominator;
        uint256 requiredPaymentAmount = fullPaymentAmount - royaltyAmount;

        if (secondOrder.currencyContract == address(0)) {
            /* Reentrancy prevented by reentrancyGuard modifier */
            /* This will allow for the transaction being a bit late and requiring less payment when combined with atomic match */
            /* Todo: maybe refund? */
            require(requiredPaymentAmount >= msg.value, "Supplied less than required");

            if (royaltyAmount > 0) {
                require(royaltyAddress != address(0));
                (bool success,) = royaltyAddress.call{value: royaltyAmount}("");
                require(success, "native token transfer failed. royalties");
            }

            if (requiredPaymentAmount > 0) {
                (bool success,) = lease.lessor.call{value: requiredPaymentAmount}("");
                require(success, "native token transfer failed.");
            }
        } else {
            /* Execute first call, assert success. */

            IERC20 paymentContractAddress = IERC20(secondOrder.currencyContract);
            if (royaltyAmount > 0) { 
                require(royaltyAddress != address(0));
                require(paymentContractAddress.transferFrom(secondOrder.maker, royaltyAddress, royaltyAmount), "Payment for asset failed. royalties");
            }
            
            if (requiredPaymentAmount > 0) {
                require(paymentContractAddress.transferFrom(secondOrder.maker, lease.lessor, requiredPaymentAmount), "Payment for asset failed");
            }
        }
        
        updateLease(
            secondOrder.tokenId,
            lease.lessor,
            getLessee(secondOrder.tokenId),
            extendToTime,
            lease.offerHash,
            lease.extendPeriodStartTime
        );
    }

    function atomicMatchAndExtendLease(
        LeaseOrder memory firstOrder,
        LeaseOrder memory secondOrder,
        bytes memory firstSignature,
        bytes memory secondSignature, 
        uint256 extendToTime
    ) 
        external
        payable
    {
        atomicMatch(firstOrder, secondOrder, firstSignature, secondSignature);
        extendLease(secondOrder, extendToTime);
    }

    function unleaseDomain(uint256 tokenId) external onlyLessee(tokenId) {
        updateLease(
            tokenId,
            leases[tokenId].lessor,
            address(0),
            0,
            bytes32(0),
            0
        );
    }

    function getLeaseInfo(uint256 tokenId)
        external
        view
        returns (
            address lessor,
            address lessee,
            bytes32 offerHash,
            uint256 endTime
        )
    {
        Lease storage lease = leases[tokenId];
        lessor = lease.lessor;
        endTime = lease.endTime;
        lessee = getLessee(tokenId);
        offerHash = lease.offerHash;
    }

    // --------- IRecordStorage ---------
    function set(
        string calldata key,
        string calldata value,
        uint256 tokenId
    ) external onlyLessee(tokenId) {
        tokenAddress.set(key, value, tokenId);
    }

    function setMany(
        string[] memory keys,
        string[] memory values,
        uint256 tokenId
    ) external onlyLessee(tokenId) {
        tokenAddress.setMany(keys, values, tokenId);
    }

    function setByHash(
        uint256 keyHash,
        string calldata value,
        uint256 tokenId
    ) external onlyLessee(tokenId) {
        tokenAddress.setByHash(keyHash, value, tokenId);
    }

    function setManyByHash(
        uint256[] calldata keyHashes,
        string[] calldata values,
        uint256 tokenId
    ) external onlyLessee(tokenId) {
        tokenAddress.setManyByHash(keyHashes, values, tokenId);
    }

    function reconfigure(
        string[] memory keys,
        string[] memory values,
        uint256 tokenId
    ) external onlyLessee(tokenId) {
        tokenAddress.reconfigure(keys, values, tokenId);
    }

    function reset(uint256 tokenId) external onlyLessee(tokenId) {
        tokenAddress.reset(tokenId);
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }
}
    