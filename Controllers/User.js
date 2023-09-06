const ErrorHandler = require("../Utils/ErrorHandler");
const catchAsyncError = require("../Middlewares/CatchAsyncError");
const sendToken = require("../Utils/JwtToken");
const BUser = require("../Models/UserSchema");
const crypto = require("crypto");

//register user
exports.createUser = catchAsyncError(async (req, res, next) => {
  const { name, email, password } = req.body;
  const user = await BUser.create({
    name,
    email,
    password,
  });
  sendToken(user, 201, res);
  // const token = user.getJWTToken();
  // res.status(201).json({
  //   success: true,
  //   token,
  // });
});

//login user
exports.loginUser = catchAsyncError(async (req, res, next) => {
  const { email, password } = req.body;
  //checking if user has given email or password
  if (!email || !password) {
    return next(new ErrorHandler("please enter email and password", 401));
  }

  const user = await BUser.findOne({ email }).select("+password");
  if (!user) {
    return next(new ErrorHandler("Invalid email or password", 401));
  }

  const isPasswordMatched = await user.comparePassword(password);

  if (!isPasswordMatched) {
    return next(new ErrorHandler("Invalid email or password", 401));
  }
  sendToken(user, 200, res);
// const token = user.getJWTToken();
//   res.status(201).json({
//     success: true,
//     token,
//   });
});

//update password
exports.updatePassword = async (req, res, next) => {
  console.log("+++++++++++++++++", req);
  try {
    const user = await BUser.findById(req.user.id).select("+password");
    const isPasswordMatched = await user.comparePassword(req.body.oldPassword);
    if (!isPasswordMatched) {
      return next(new ErrorHandler("Old password is incorrect", 400));
    }
    if (req.body.newPassword !== req.body.confirmPassword) {
      return next(new ErrorHandler(`password does not match`));
    }
    user.password = req.body.newPassword;
    await user.save();
    sendToken(user, 200, res);
  } catch (err) {
    next(new ErrorHandler(err));
  }
};

//Logout
exports.logOut = catchAsyncError(async (req, res, next) => {
  res.cookie("token", null, {
    expires: new Date(Date.now()),
    httpOnly: true,
  });

  res.status(200).json({
    success: true,
    message: "Logged out",
  });
});

//get all Users
exports.getAllUsers = catchAsyncError(async (req, res, next) => {
  const users = await BUser.find();
  res.status(200).json({
    success: true,
    users,
  });
});
//get  single user
exports.getSingleUser = catchAsyncError(async (req, res, next) => {
  const user = await BUser.findById(req.params.id);
  if (!user) {
    return next(
      new ErrorHandler(`User does not exist with id:${req.params.id}`)
    );
  }
  res.status(200).json({
    success: true,
    user,
  });
});
