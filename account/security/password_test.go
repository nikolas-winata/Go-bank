package password

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// type PasswordHashingTestSuite struct {
// 	suite.Suite
// }

// func simplePasswordHashAndValidate(passwordLength uint32, t *testing.T) {
// 	password := GenerateRandomString(passwordLength)
// 	hashedPassword, err := passwordHash(password)
// 	if err != nil {
// 		t.Error("error when hashing")
// 	}

// 	if hashedPassword == "" {
// 		t.Error("empty passwordhash")
// 	}

// 	err = validatePassword(hashedPassword, password)
// 	if err != nil {
// 		t.Error(err.Error())
// 	}
// }
// func TestSimplePasswordHashAndValidate(t *testing.T) {
// 	simplePasswordHashAndValidate(8, t)
// 	simplePasswordHashAndValidate(16, t)
// 	simplePasswordHashAndValidate(32, t)
// 	simplePasswordHashAndValidate(64, t)

// }

// func TestInvalidPasswordHash() {
// 	password := ""
// 	hashedPassword, err := passwordHash(password)
// 	suite.Require().Equal(errors.New("hey"), err)
// 	suite.Require().Empty(hashedPassword)

// 	suite.Require().Nil(err)
// }

type PasswordHashingTestSuite struct {
	suite.Suite
}

func (suite *PasswordHashingTestSuite) simplePasswordHashAndValidate(passwordLength uint32) {
	password := GenerateRandomString(passwordLength)
	hashedPassword, err := passwordHash(password)
	suite.Require().NoError(err)
	suite.Require().NotEmpty(hashedPassword)

	err = validatePassword(hashedPassword, password)
	suite.Require().NoError(err)
}

func (suite *PasswordHashingTestSuite) TestSimplePasswordHashAndValidate() {
	suite.simplePasswordHashAndValidate(8)
	suite.simplePasswordHashAndValidate(16)
	suite.simplePasswordHashAndValidate(32)
	suite.simplePasswordHashAndValidate(64)
}

func (suite *PasswordHashingTestSuite) TestInvalidPasswordHash() {
	password := ""
	hashedPassword, err := passwordHash(password)
	suite.Require().Error(err)
	suite.Require().Empty(hashedPassword)
}

func TestSuite(t *testing.T) {
	suite.Run(t, new(PasswordHashingTestSuite))
}
