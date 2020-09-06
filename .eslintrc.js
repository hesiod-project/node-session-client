module.exports = {
  env: {
    commonjs: true,
    es2020: true,
    node: true
  },
  extends: [
    'standard'
  ],
  parserOptions: {
    ecmaVersion: 11
  },
  rules: {
    'no-multi-spaces': 'off',
    'spaced-comment': 'off',
    'space-before-function-paren': ['error', {anonymous: 'never', named: 'never', asyncArrow: 'always'}],
    'no-var': 'error',
    'no-constant-condition': 'off',
    'comma-dangle': 'off',
    'object-curly-spacing': 'off',
  }
}
